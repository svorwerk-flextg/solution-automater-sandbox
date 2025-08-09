package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Configuration for the database proxy
type Config struct {
	Listeners []ListenerConfig `json:"listeners"`
	Backends  []BackendConfig  `json:"backends"`
	Security  SecurityConfig   `json:"security"`
	Logging   LoggingConfig    `json:"logging"`
}

type ListenerConfig struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
}

type BackendConfig struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Database string `json:"database"`
	TLS      bool   `json:"tls"`
}

type SecurityConfig struct {
	EnforceReadOnly bool     `json:"enforce_read_only"`
	BlockedCommands []string `json:"blocked_commands"`
	AllowedIPs      []string `json:"allowed_ips"`
	AuditEnabled    bool     `json:"audit_enabled"`
}

type LoggingConfig struct {
	Level      string `json:"level"`
	AuditPath  string `json:"audit_path"`
	MaxSize    int    `json:"max_size_mb"`
	MaxBackups int    `json:"max_backups"`
}

// SQLInterceptor analyzes and blocks write operations
type SQLInterceptor struct {
	writePatterns []*regexp.Regexp
	auditLogger   *AuditLogger
	mu            sync.RWMutex
}

func NewSQLInterceptor(auditLogger *AuditLogger) *SQLInterceptor {
	patterns := []string{
		// DML write operations
		`(?i)^\s*(INSERT|UPDATE|DELETE|REPLACE|MERGE)\s+`,
		`(?i)^\s*(TRUNCATE|DROP|CREATE|ALTER)\s+`,
		
		// DDL operations
		`(?i)^\s*(GRANT|REVOKE|DENY)\s+`,
		`(?i)^\s*(BACKUP|RESTORE)\s+`,
		
		// Stored procedures that might write
		`(?i)^\s*(EXEC|EXECUTE|CALL)\s+.*_(INSERT|UPDATE|DELETE|CREATE|DROP)`,
		
		// MongoDB write operations
		`(?i)(insert|update|delete|drop|create|remove)\s*\(`,
		`(?i)\$set|\$unset|\$push|\$pull|\$inc`,
		
		// Dangerous operations
		`(?i)^\s*(SHUTDOWN|KILL)\s+`,
	}
	
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		compiled = append(compiled, regexp.MustCompile(pattern))
	}
	
	return &SQLInterceptor{
		writePatterns: compiled,
		auditLogger:   auditLogger,
	}
}

func (si *SQLInterceptor) IsWriteOperation(query string) bool {
	si.mu.RLock()
	defer si.mu.RUnlock()
	
	// Normalize query
	query = strings.TrimSpace(query)
	
	// Check against all patterns
	for _, pattern := range si.writePatterns {
		if pattern.MatchString(query) {
			return true
		}
	}
	
	// Additional checks for sneaky write attempts
	lowerQuery := strings.ToLower(query)
	dangerousKeywords := []string{
		"into", "set", "values", "modify", "cascade",
		"constraint", "index", "trigger", "procedure",
	}
	
	for _, keyword := range dangerousKeywords {
		if strings.Contains(lowerQuery, keyword) {
			// Log for manual review
			si.auditLogger.LogSuspicious(query, "Contains dangerous keyword: "+keyword)
		}
	}
	
	return false
}

// ProxyConnection handles individual client connections
type ProxyConnection struct {
	clientConn   net.Conn
	backendConn  net.Conn
	interceptor  *SQLInterceptor
	auditLogger  *AuditLogger
	sessionID    string
	protocol     string
}

func (pc *ProxyConnection) Handle() {
	defer pc.Close()
	
	// Log connection
	pc.auditLogger.LogConnection(pc.sessionID, pc.clientConn.RemoteAddr().String())
	
	// Create channels for bidirectional copying
	clientErr := make(chan error, 1)
	backendErr := make(chan error, 1)
	
	// Client -> Backend (with interception)
	go func() {
		buffer := make([]byte, 32*1024)
		for {
			n, err := pc.clientConn.Read(buffer)
			if err != nil {
				clientErr <- err
				return
			}
			
			// Intercept and analyze
			data := buffer[:n]
			if pc.shouldIntercept(data) {
				query := pc.extractQuery(data)
				if pc.interceptor.IsWriteOperation(query) {
					// Block the operation
					pc.sendError("Write operations are not permitted in sandbox environment")
					pc.auditLogger.LogBlocked(pc.sessionID, query)
					continue
				}
				pc.auditLogger.LogQuery(pc.sessionID, query, "ALLOWED")
			}
			
			// Forward to backend
			_, err = pc.backendConn.Write(data)
			if err != nil {
				clientErr <- err
				return
			}
		}
	}()
	
	// Backend -> Client (transparent)
	go func() {
		_, err := io.Copy(pc.clientConn, pc.backendConn)
		backendErr <- err
	}()
	
	// Wait for either direction to fail
	select {
	case err := <-clientErr:
		if err != io.EOF {
			log.Printf("Client error: %v", err)
		}
	case err := <-backendErr:
		if err != io.EOF {
			log.Printf("Backend error: %v", err)
		}
	}
}

func (pc *ProxyConnection) shouldIntercept(data []byte) bool {
	// Simple heuristic - look for SQL-like patterns
	// In production, use protocol-specific parsing
	str := string(data)
	return len(str) > 5 && (strings.Contains(str, "SELECT") || 
		strings.Contains(str, "INSERT") || 
		strings.Contains(str, "UPDATE") ||
		strings.Contains(str, "DELETE"))
}

func (pc *ProxyConnection) extractQuery(data []byte) string {
	// Protocol-specific query extraction
	// This is simplified - real implementation needs proper protocol parsing
	switch pc.protocol {
	case "mysql":
		return pc.extractMySQLQuery(data)
	case "mssql":
		return pc.extractMSSQLQuery(data)
	case "mongodb":
		return pc.extractMongoQuery(data)
	default:
		return string(data)
	}
}

func (pc *ProxyConnection) extractMySQLQuery(data []byte) string {
	// MySQL protocol parsing (simplified)
	if len(data) > 5 {
		// Skip packet header
		return string(data[5:])
	}
	return string(data)
}

func (pc *ProxyConnection) extractMSSQLQuery(data []byte) string {
	// TDS protocol parsing (simplified)
	return string(data)
}

func (pc *ProxyConnection) extractMongoQuery(data []byte) string {
	// MongoDB wire protocol parsing (simplified)
	return string(data)
}

func (pc *ProxyConnection) sendError(message string) {
	// Send protocol-specific error message
	errorPacket := pc.formatError(message)
	pc.clientConn.Write(errorPacket)
}

func (pc *ProxyConnection) formatError(message string) []byte {
	// Protocol-specific error formatting
	switch pc.protocol {
	case "mysql":
		return pc.formatMySQLError(message)
	case "mssql":
		return pc.formatMSSQLError(message)
	default:
		return []byte(message)
	}
}

func (pc *ProxyConnection) formatMySQLError(message string) []byte {
	// MySQL error packet format
	// Simplified - real implementation needs proper packet construction
	return []byte(fmt.Sprintf("ERROR: %s", message))
}

func (pc *ProxyConnection) formatMSSQLError(message string) []byte {
	// TDS error format
	return []byte(fmt.Sprintf("ERROR: %s", message))
}

func (pc *ProxyConnection) Close() {
	if pc.clientConn != nil {
		pc.clientConn.Close()
	}
	if pc.backendConn != nil {
		pc.backendConn.Close()
	}
	pc.auditLogger.LogDisconnection(pc.sessionID)
}

// AuditLogger handles security audit logging
type AuditLogger struct {
	mu       sync.Mutex
	file     *os.File
	encoder  *json.Encoder
}

type AuditEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	SessionID   string    `json:"session_id"`
	Type        string    `json:"type"`
	Source      string    `json:"source"`
	Query       string    `json:"query,omitempty"`
	Status      string    `json:"status"`
	Message     string    `json:"message,omitempty"`
}

func NewAuditLogger(path string) (*AuditLogger, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	
	return &AuditLogger{
		file:    file,
		encoder: json.NewEncoder(file),
	}, nil
}

func (al *AuditLogger) LogConnection(sessionID, source string) {
	al.log(AuditEntry{
		Timestamp: time.Now(),
		SessionID: sessionID,
		Type:      "CONNECTION",
		Source:    source,
		Status:    "ESTABLISHED",
	})
}

func (al *AuditLogger) LogQuery(sessionID, query, status string) {
	al.log(AuditEntry{
		Timestamp: time.Now(),
		SessionID: sessionID,
		Type:      "QUERY",
		Query:     query,
		Status:    status,
	})
}

func (al *AuditLogger) LogBlocked(sessionID, query string) {
	al.log(AuditEntry{
		Timestamp: time.Now(),
		SessionID: sessionID,
		Type:      "BLOCKED",
		Query:     query,
		Status:    "DENIED",
		Message:   "Write operation blocked by security policy",
	})
}

func (al *AuditLogger) LogSuspicious(query, reason string) {
	al.log(AuditEntry{
		Timestamp: time.Now(),
		Type:      "SUSPICIOUS",
		Query:     query,
		Status:    "REVIEW",
		Message:   reason,
	})
}

func (al *AuditLogger) LogDisconnection(sessionID string) {
	al.log(AuditEntry{
		Timestamp: time.Now(),
		SessionID: sessionID,
		Type:      "DISCONNECTION",
		Status:    "CLOSED",
	})
}

func (al *AuditLogger) log(entry AuditEntry) {
	al.mu.Lock()
	defer al.mu.Unlock()
	
	if err := al.encoder.Encode(entry); err != nil {
		log.Printf("Failed to write audit log: %v", err)
	}
}

func (al *AuditLogger) Close() error {
	return al.file.Close()
}

// Proxy server main structure
type ProxyServer struct {
	config      *Config
	interceptor *SQLInterceptor
	auditLogger *AuditLogger
	listeners   []net.Listener
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
}

func NewProxyServer(config *Config) (*ProxyServer, error) {
	auditLogger, err := NewAuditLogger(config.Logging.AuditPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit logger: %w", err)
	}
	
	interceptor := NewSQLInterceptor(auditLogger)
	ctx, cancel := context.WithCancel(context.Background())
	
	return &ProxyServer{
		config:      config,
		interceptor: interceptor,
		auditLogger: auditLogger,
		ctx:         ctx,
		cancel:      cancel,
	}, nil
}

func (ps *ProxyServer) Start() error {
	// Start listeners for each database type
	for _, listenerConfig := range ps.config.Listeners {
		listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", listenerConfig.Address, listenerConfig.Port))
		if err != nil {
			return fmt.Errorf("failed to start listener %s: %w", listenerConfig.Name, err)
		}
		
		ps.listeners = append(ps.listeners, listener)
		ps.wg.Add(1)
		
		go ps.acceptConnections(listener, listenerConfig)
		log.Printf("Started listener %s on %s:%d", listenerConfig.Name, listenerConfig.Address, listenerConfig.Port)
	}
	
	return nil
}

func (ps *ProxyServer) acceptConnections(listener net.Listener, config ListenerConfig) {
	defer ps.wg.Done()
	
	for {
		select {
		case <-ps.ctx.Done():
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				if ps.ctx.Err() != nil {
					return
				}
				log.Printf("Accept error: %v", err)
				continue
			}
			
			// Verify client IP if configured
			if !ps.isAllowedIP(conn.RemoteAddr()) {
				conn.Close()
				ps.auditLogger.LogBlocked("", fmt.Sprintf("Connection from %s denied", conn.RemoteAddr()))
				continue
			}
			
			go ps.handleConnection(conn, config)
		}
	}
}

func (ps *ProxyServer) isAllowedIP(addr net.Addr) bool {
	if len(ps.config.Security.AllowedIPs) == 0 {
		return true // No restrictions
	}
	
	// Extract IP from address
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	
	// Check against allowed IPs
	for _, allowed := range ps.config.Security.AllowedIPs {
		if allowed == host || allowed == "0.0.0.0" {
			return true
		}
		
		// Check CIDR ranges
		_, cidr, err := net.ParseCIDR(allowed)
		if err == nil && cidr.Contains(net.ParseIP(host)) {
			return true
		}
	}
	
	return false
}

func (ps *ProxyServer) handleConnection(clientConn net.Conn, listenerConfig ListenerConfig) {
	// Find matching backend
	backend := ps.findBackend(listenerConfig.Protocol)
	if backend == nil {
		clientConn.Close()
		return
	}
	
	// Connect to backend
	backendAddr := fmt.Sprintf("%s:%d", backend.Address, backend.Port)
	backendConn, err := net.Dial("tcp", backendAddr)
	if err != nil {
		log.Printf("Failed to connect to backend %s: %v", backend.Name, err)
		clientConn.Close()
		return
	}
	
	// Create proxy connection
	sessionID := generateSessionID()
	proxy := &ProxyConnection{
		clientConn:  clientConn,
		backendConn: backendConn,
		interceptor: ps.interceptor,
		auditLogger: ps.auditLogger,
		sessionID:   sessionID,
		protocol:    listenerConfig.Protocol,
	}
	
	// Handle the connection
	proxy.Handle()
}

func (ps *ProxyServer) findBackend(protocol string) *BackendConfig {
	for _, backend := range ps.config.Backends {
		if backend.Type == protocol {
			return &backend
		}
	}
	return nil
}

func (ps *ProxyServer) Stop() {
	log.Println("Stopping proxy server...")
	ps.cancel()
	
	// Close all listeners
	for _, listener := range ps.listeners {
		listener.Close()
	}
	
	// Wait for all connections to close
	ps.wg.Wait()
	
	// Close audit logger
	ps.auditLogger.Close()
	
	log.Println("Proxy server stopped")
}

func generateSessionID() string {
	return fmt.Sprintf("%d-%d", time.Now().Unix(), os.Getpid())
}

func main() {
	// Load configuration
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "/etc/proxy/config.yaml"
	}
	
	config, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	
	// Create and start proxy server
	server, err := NewProxyServer(config)
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}
	
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
	}
	
	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	
	// Graceful shutdown
	server.Stop()
}

func loadConfig(path string) (*Config, error) {
	// For now, return a default configuration
	// In production, load from YAML/JSON file
	return &Config{
		Listeners: []ListenerConfig{
			{Name: "mysql", Protocol: "mysql", Address: "0.0.0.0", Port: 3306},
			{Name: "mssql", Protocol: "mssql", Address: "0.0.0.0", Port: 1433},
			{Name: "mongodb", Protocol: "mongodb", Address: "0.0.0.0", Port: 27017},
		},
		Backends: []BackendConfig{
			{Name: "mysql-prod", Type: "mysql", Address: "prod-mysql.internal", Port: 3306},
			{Name: "mssql-prod", Type: "mssql", Address: "prod-mssql.internal", Port: 1433},
			{Name: "mongodb-prod", Type: "mongodb", Address: "prod-mongo.internal", Port: 27017},
		},
		Security: SecurityConfig{
			EnforceReadOnly: true,
			BlockedCommands: []string{"INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER"},
			AuditEnabled:    true,
		},
		Logging: LoggingConfig{
			Level:      "info",
			AuditPath:  "/var/log/proxy/audit.json",
			MaxSize:    100,
			MaxBackups: 10,
		},
	}, nil
}