"""
Cloud Security Manager

Comprehensive security management across cloud platforms:
- Cross-cloud IAM and RBAC management
- Encryption key management
- Compliance monitoring and reporting
- Security scanning and vulnerability assessment
- Network security management
- Audit logging and SIEM integration
"""

import os
import json
import logging
import hashlib
import secrets
from typing import Dict, List, Optional, Any, Tuple, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import re
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import boto3
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
import yaml
from collections import defaultdict
import threading
import uuid

logger = logging.getLogger(__name__)


class SecurityLevel(Enum):
    """Security classification levels"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"


class ComplianceFramework(Enum):
    """Compliance frameworks"""
    SOC2 = "soc2"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    PCI_DSS = "pci_dss"
    ISO_27001 = "iso_27001"
    NIST = "nist"


class ThreatLevel(Enum):
    """Security threat levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SecurityPolicy:
    """Security policy definition"""
    name: str
    description: str
    rules: List[Dict[str, Any]]
    compliance_frameworks: List[ComplianceFramework]
    enforcement_level: str = "mandatory"  # mandatory, advisory
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)


@dataclass
class SecurityIncident:
    """Security incident record"""
    incident_id: str
    timestamp: datetime
    threat_level: ThreatLevel
    source: str
    description: str
    affected_resources: List[str]
    remediation_status: str = "open"  # open, in_progress, resolved
    remediation_actions: List[str] = field(default_factory=list)


@dataclass
class EncryptionKey:
    """Encryption key metadata"""
    key_id: str
    algorithm: str
    key_size: int
    created_at: datetime
    rotation_schedule: timedelta
    last_rotated: Optional[datetime] = None
    usage_count: int = 0
    status: str = "active"  # active, rotating, deprecated, revoked


@dataclass
class AccessControl:
    """Access control entry"""
    principal: str  # user, role, or service account
    resource: str
    permissions: List[str]
    conditions: Optional[Dict[str, Any]] = None
    expires_at: Optional[datetime] = None
    created_by: str = "system"
    created_at: datetime = field(default_factory=datetime.now)


class CloudSecurityManager:
    """Comprehensive security manager for multi-cloud environments"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        self.policies = {}
        self.incidents = {}
        self.encryption_keys = {}
        self.access_controls = defaultdict(list)
        self.audit_log = []
        self._key_stores = {}
        self._compliance_cache = {}
        self._vulnerability_scanner = None
        self._siem_client = None
        self._lock = threading.Lock()
        self._is_initialized = False
        
    def initialize(self):
        """Initialize the security manager"""
        if self._is_initialized:
            return
            
        try:
            # Load configuration
            if self.config_file:
                self._load_configuration()
                
            # Initialize key management systems
            self._initialize_key_stores()
            
            # Initialize compliance monitoring
            self._initialize_compliance_monitoring()
            
            # Initialize vulnerability scanner
            self._initialize_vulnerability_scanner()
            
            # Initialize SIEM integration
            self._initialize_siem()
            
            # Load default security policies
            self._load_default_policies()
            
            self._is_initialized = True
            logger.info("Cloud security manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize security manager: {e}")
            raise
            
    def _load_configuration(self):
        """Load security configuration"""
        with open(self.config_file, 'r') as f:
            self.config = yaml.safe_load(f)
            
    def _initialize_key_stores(self):
        """Initialize cloud key management systems"""
        # AWS KMS
        if 'aws' in self.config.get('key_stores', {}):
            self._key_stores['aws'] = boto3.client('kms',
                region_name=self.config['key_stores']['aws'].get('region', 'us-east-1')
            )
            
        # Azure Key Vault
        if 'azure' in self.config.get('key_stores', {}):
            credential = DefaultAzureCredential()
            vault_url = self.config['key_stores']['azure']['vault_url']
            self._key_stores['azure'] = SecretClient(
                vault_url=vault_url,
                credential=credential
            )
            
    def _initialize_compliance_monitoring(self):
        """Initialize compliance monitoring systems"""
        # Load compliance rules
        self.compliance_rules = self.config.get('compliance_rules', {})
        
        # Initialize compliance scanners
        self.compliance_scanners = {}
        
    def _initialize_vulnerability_scanner(self):
        """Initialize vulnerability scanning"""
        # This would integrate with tools like AWS Inspector, Azure Security Center, etc.
        pass
        
    def _initialize_siem(self):
        """Initialize SIEM integration"""
        # This would integrate with tools like Splunk, ELK, Azure Sentinel, etc.
        pass
        
    def _load_default_policies(self):
        """Load default security policies"""
        default_policies = [
            SecurityPolicy(
                name="password_policy",
                description="Password complexity requirements",
                rules=[
                    {"type": "min_length", "value": 12},
                    {"type": "require_uppercase", "value": True},
                    {"type": "require_lowercase", "value": True},
                    {"type": "require_numbers", "value": True},
                    {"type": "require_special", "value": True},
                    {"type": "max_age_days", "value": 90}
                ],
                compliance_frameworks=[ComplianceFramework.SOC2, ComplianceFramework.ISO_27001]
            ),
            SecurityPolicy(
                name="mfa_policy",
                description="Multi-factor authentication requirements",
                rules=[
                    {"type": "require_mfa", "value": True},
                    {"type": "allowed_methods", "value": ["totp", "sms", "hardware_key"]},
                    {"type": "grace_period_days", "value": 7}
                ],
                compliance_frameworks=[ComplianceFramework.SOC2, ComplianceFramework.PCI_DSS]
            ),
            SecurityPolicy(
                name="encryption_policy",
                description="Data encryption requirements",
                rules=[
                    {"type": "encryption_at_rest", "value": True},
                    {"type": "encryption_in_transit", "value": True},
                    {"type": "min_key_size", "value": 256},
                    {"type": "allowed_algorithms", "value": ["AES-256", "RSA-2048"]}
                ],
                compliance_frameworks=[ComplianceFramework.HIPAA, ComplianceFramework.GDPR]
            ),
            SecurityPolicy(
                name="network_security_policy",
                description="Network security requirements",
                rules=[
                    {"type": "deny_public_access", "value": True},
                    {"type": "require_vpc", "value": True},
                    {"type": "allowed_ports", "value": [443, 22]},
                    {"type": "require_waf", "value": True}
                ],
                compliance_frameworks=[ComplianceFramework.PCI_DSS, ComplianceFramework.NIST]
            )
        ]
        
        for policy in default_policies:
            self.add_policy(policy)
            
    # Policy Management
    def add_policy(self, policy: SecurityPolicy) -> str:
        """Add a security policy"""
        policy_id = f"policy_{policy.name}_{uuid.uuid4().hex[:8]}"
        
        with self._lock:
            self.policies[policy_id] = policy
            
        self._audit_log_event("policy_added", {
            "policy_id": policy_id,
            "policy_name": policy.name
        })
        
        logger.info(f"Added security policy: {policy_id}")
        return policy_id
        
    def update_policy(self, policy_id: str, updates: Dict[str, Any]):
        """Update an existing policy"""
        with self._lock:
            if policy_id not in self.policies:
                raise ValueError(f"Policy {policy_id} not found")
                
            policy = self.policies[policy_id]
            
            for key, value in updates.items():
                if hasattr(policy, key):
                    setattr(policy, key, value)
                    
            policy.updated_at = datetime.now()
            
        self._audit_log_event("policy_updated", {
            "policy_id": policy_id,
            "updates": list(updates.keys())
        })
        
    def evaluate_policy(self, policy_id: str, context: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Evaluate a policy against a given context"""
        policy = self.policies.get(policy_id)
        if not policy:
            return False, [f"Policy {policy_id} not found"]
            
        violations = []
        
        for rule in policy.rules:
            rule_type = rule.get('type')
            rule_value = rule.get('value')
            
            # Evaluate different rule types
            if rule_type == 'min_length':
                if len(context.get('password', '')) < rule_value:
                    violations.append(f"Password must be at least {rule_value} characters")
                    
            elif rule_type == 'require_mfa':
                if rule_value and not context.get('mfa_enabled', False):
                    violations.append("Multi-factor authentication is required")
                    
            elif rule_type == 'encryption_at_rest':
                if rule_value and not context.get('encrypted_at_rest', False):
                    violations.append("Data must be encrypted at rest")
                    
            # Add more rule evaluations as needed
            
        return len(violations) == 0, violations
        
    # Access Control Management
    def grant_access(self, principal: str, resource: str, 
                    permissions: List[str], conditions: Optional[Dict] = None,
                    expires_at: Optional[datetime] = None) -> str:
        """Grant access to a resource"""
        access_id = f"access_{uuid.uuid4().hex}"
        
        access_control = AccessControl(
            principal=principal,
            resource=resource,
            permissions=permissions,
            conditions=conditions,
            expires_at=expires_at
        )
        
        with self._lock:
            self.access_controls[resource].append(access_control)
            
        self._audit_log_event("access_granted", {
            "access_id": access_id,
            "principal": principal,
            "resource": resource,
            "permissions": permissions
        })
        
        logger.info(f"Granted access: {principal} -> {resource}")
        return access_id
        
    def revoke_access(self, principal: str, resource: str):
        """Revoke access to a resource"""
        with self._lock:
            if resource in self.access_controls:
                self.access_controls[resource] = [
                    ac for ac in self.access_controls[resource]
                    if ac.principal != principal
                ]
                
        self._audit_log_event("access_revoked", {
            "principal": principal,
            "resource": resource
        })
        
        logger.info(f"Revoked access: {principal} -> {resource}")
        
    def check_access(self, principal: str, resource: str, 
                    permission: str, context: Optional[Dict] = None) -> bool:
        """Check if a principal has access to a resource"""
        with self._lock:
            access_list = self.access_controls.get(resource, [])
            
            for access in access_list:
                if access.principal != principal:
                    continue
                    
                if permission not in access.permissions:
                    continue
                    
                # Check expiration
                if access.expires_at and datetime.now() > access.expires_at:
                    continue
                    
                # Check conditions
                if access.conditions and context:
                    if not self._evaluate_conditions(access.conditions, context):
                        continue
                        
                return True
                
        return False
        
    def _evaluate_conditions(self, conditions: Dict[str, Any], 
                           context: Dict[str, Any]) -> bool:
        """Evaluate access conditions"""
        for key, expected_value in conditions.items():
            actual_value = context.get(key)
            
            if isinstance(expected_value, list):
                if actual_value not in expected_value:
                    return False
            else:
                if actual_value != expected_value:
                    return False
                    
        return True
        
    # Encryption Management
    def create_encryption_key(self, algorithm: str = "AES-256",
                            key_size: int = 256,
                            rotation_days: int = 90) -> str:
        """Create a new encryption key"""
        key_id = f"key_{uuid.uuid4().hex}"
        
        # Generate key based on algorithm
        if algorithm.startswith("AES"):
            key = Fernet.generate_key()
        elif algorithm.startswith("RSA"):
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=default_backend()
            )
            key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
        # Store key in appropriate key store
        self._store_key(key_id, key)
        
        # Create metadata
        encryption_key = EncryptionKey(
            key_id=key_id,
            algorithm=algorithm,
            key_size=key_size,
            created_at=datetime.now(),
            rotation_schedule=timedelta(days=rotation_days)
        )
        
        with self._lock:
            self.encryption_keys[key_id] = encryption_key
            
        self._audit_log_event("key_created", {
            "key_id": key_id,
            "algorithm": algorithm,
            "key_size": key_size
        })
        
        logger.info(f"Created encryption key: {key_id}")
        return key_id
        
    def rotate_key(self, key_id: str) -> str:
        """Rotate an encryption key"""
        with self._lock:
            if key_id not in self.encryption_keys:
                raise ValueError(f"Key {key_id} not found")
                
            old_key = self.encryption_keys[key_id]
            
            # Create new key
            new_key_id = self.create_encryption_key(
                algorithm=old_key.algorithm,
                key_size=old_key.key_size,
                rotation_days=int(old_key.rotation_schedule.total_seconds() / 86400)
            )
            
            # Update old key status
            old_key.status = "rotating"
            old_key.last_rotated = datetime.now()
            
        self._audit_log_event("key_rotated", {
            "old_key_id": key_id,
            "new_key_id": new_key_id
        })
        
        logger.info(f"Rotated key: {key_id} -> {new_key_id}")
        return new_key_id
        
    def encrypt_data(self, data: bytes, key_id: str,
                    context: Optional[Dict] = None) -> bytes:
        """Encrypt data using specified key"""
        key_metadata = self.encryption_keys.get(key_id)
        if not key_metadata:
            raise ValueError(f"Key {key_id} not found")
            
        if key_metadata.status != "active":
            raise ValueError(f"Key {key_id} is not active")
            
        # Retrieve key from store
        key = self._retrieve_key(key_id)
        
        # Encrypt based on algorithm
        if key_metadata.algorithm.startswith("AES"):
            cipher = Fernet(key)
            encrypted = cipher.encrypt(data)
        else:
            # Implement other algorithms as needed
            raise NotImplementedError(f"Encryption not implemented for {key_metadata.algorithm}")
            
        # Update usage count
        with self._lock:
            key_metadata.usage_count += 1
            
        self._audit_log_event("data_encrypted", {
            "key_id": key_id,
            "data_size": len(data),
            "context": context
        })
        
        return encrypted
        
    def decrypt_data(self, encrypted_data: bytes, key_id: str,
                    context: Optional[Dict] = None) -> bytes:
        """Decrypt data using specified key"""
        key_metadata = self.encryption_keys.get(key_id)
        if not key_metadata:
            raise ValueError(f"Key {key_id} not found")
            
        # Retrieve key from store
        key = self._retrieve_key(key_id)
        
        # Decrypt based on algorithm
        if key_metadata.algorithm.startswith("AES"):
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_data)
        else:
            # Implement other algorithms as needed
            raise NotImplementedError(f"Decryption not implemented for {key_metadata.algorithm}")
            
        self._audit_log_event("data_decrypted", {
            "key_id": key_id,
            "data_size": len(encrypted_data),
            "context": context
        })
        
        return decrypted
        
    def _store_key(self, key_id: str, key: bytes):
        """Store key in appropriate key management system"""
        # This would store in AWS KMS, Azure Key Vault, etc.
        # For now, store locally (not for production!)
        # In production, use proper key management services
        pass
        
    def _retrieve_key(self, key_id: str) -> bytes:
        """Retrieve key from key management system"""
        # This would retrieve from AWS KMS, Azure Key Vault, etc.
        # For now, generate a dummy key (not for production!)
        return Fernet.generate_key()
        
    # Compliance Monitoring
    def run_compliance_scan(self, frameworks: List[ComplianceFramework]) -> Dict[str, Any]:
        """Run compliance scan for specified frameworks"""
        results = {
            'scan_time': datetime.now().isoformat(),
            'frameworks': {},
            'overall_score': 0,
            'violations': []
        }
        
        for framework in frameworks:
            framework_results = self._scan_framework_compliance(framework)
            results['frameworks'][framework.value] = framework_results
            
            # Aggregate violations
            results['violations'].extend(framework_results.get('violations', []))
            
        # Calculate overall score
        if results['frameworks']:
            scores = [fr['score'] for fr in results['frameworks'].values()]
            results['overall_score'] = sum(scores) / len(scores)
            
        self._audit_log_event("compliance_scan_completed", {
            "frameworks": [f.value for f in frameworks],
            "overall_score": results['overall_score'],
            "violation_count": len(results['violations'])
        })
        
        return results
        
    def _scan_framework_compliance(self, framework: ComplianceFramework) -> Dict[str, Any]:
        """Scan compliance for a specific framework"""
        rules = self.compliance_rules.get(framework.value, [])
        
        results = {
            'framework': framework.value,
            'score': 100,
            'violations': [],
            'passed_rules': 0,
            'total_rules': len(rules)
        }
        
        for rule in rules:
            passed, violation = self._evaluate_compliance_rule(rule)
            
            if passed:
                results['passed_rules'] += 1
            else:
                results['violations'].append(violation)
                
        # Calculate score
        if results['total_rules'] > 0:
            results['score'] = (results['passed_rules'] / results['total_rules']) * 100
            
        return results
        
    def _evaluate_compliance_rule(self, rule: Dict[str, Any]) -> Tuple[bool, Optional[Dict]]:
        """Evaluate a single compliance rule"""
        # This would implement specific compliance checks
        # For now, return mock results
        passed = True
        violation = None
        
        if not passed:
            violation = {
                'rule_id': rule.get('id'),
                'description': rule.get('description'),
                'severity': rule.get('severity', 'medium'),
                'remediation': rule.get('remediation')
            }
            
        return passed, violation
        
    # Vulnerability Management
    def scan_vulnerabilities(self, resources: List[str]) -> List[Dict[str, Any]]:
        """Scan resources for vulnerabilities"""
        vulnerabilities = []
        
        for resource in resources:
            # This would integrate with real vulnerability scanners
            # For now, generate mock vulnerabilities
            if "database" in resource.lower():
                vulnerabilities.append({
                    'resource': resource,
                    'vulnerability': 'Unencrypted database connections',
                    'severity': ThreatLevel.HIGH.value,
                    'cve': 'CVE-2023-XXXXX',
                    'remediation': 'Enable SSL/TLS for all database connections'
                })
                
        self._audit_log_event("vulnerability_scan_completed", {
            "resources_scanned": len(resources),
            "vulnerabilities_found": len(vulnerabilities)
        })
        
        return vulnerabilities
        
    # Incident Management
    def report_incident(self, description: str, threat_level: ThreatLevel,
                       source: str, affected_resources: List[str]) -> str:
        """Report a security incident"""
        incident_id = f"incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        incident = SecurityIncident(
            incident_id=incident_id,
            timestamp=datetime.now(),
            threat_level=threat_level,
            source=source,
            description=description,
            affected_resources=affected_resources
        )
        
        with self._lock:
            self.incidents[incident_id] = incident
            
        # Trigger automated response for critical incidents
        if threat_level == ThreatLevel.CRITICAL:
            self._trigger_incident_response(incident)
            
        self._audit_log_event("incident_reported", {
            "incident_id": incident_id,
            "threat_level": threat_level.value,
            "affected_resources": affected_resources
        })
        
        logger.warning(f"Security incident reported: {incident_id}")
        return incident_id
        
    def _trigger_incident_response(self, incident: SecurityIncident):
        """Trigger automated incident response"""
        # This would implement automated response actions
        # For example:
        # - Isolate affected resources
        # - Revoke compromised credentials
        # - Trigger alerts
        # - Create snapshots for forensics
        pass
        
    def update_incident(self, incident_id: str, status: str,
                       remediation_actions: List[str]):
        """Update incident status and remediation"""
        with self._lock:
            if incident_id not in self.incidents:
                raise ValueError(f"Incident {incident_id} not found")
                
            incident = self.incidents[incident_id]
            incident.remediation_status = status
            incident.remediation_actions.extend(remediation_actions)
            
        self._audit_log_event("incident_updated", {
            "incident_id": incident_id,
            "status": status,
            "actions": remediation_actions
        })
        
    # Network Security
    def create_network_policy(self, name: str, rules: List[Dict[str, Any]]) -> str:
        """Create network security policy"""
        policy = SecurityPolicy(
            name=f"network_{name}",
            description=f"Network security policy: {name}",
            rules=rules,
            compliance_frameworks=[ComplianceFramework.NIST]
        )
        
        return self.add_policy(policy)
        
    def validate_network_configuration(self, config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate network security configuration"""
        issues = []
        
        # Check for public exposure
        if config.get('public_access', False):
            issues.append("Resources should not be publicly accessible")
            
        # Check encryption
        if not config.get('encryption_in_transit', False):
            issues.append("Network traffic must be encrypted")
            
        # Check allowed ports
        allowed_ports = config.get('allowed_ports', [])
        risky_ports = [21, 23, 135, 139, 445]  # FTP, Telnet, RPC, SMB
        
        for port in allowed_ports:
            if port in risky_ports:
                issues.append(f"Port {port} is considered risky and should not be exposed")
                
        return len(issues) == 0, issues
        
    # Audit and Logging
    def _audit_log_event(self, event_type: str, details: Dict[str, Any]):
        """Log an audit event"""
        audit_event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'details': details,
            'user': details.get('user', 'system'),
            'source_ip': details.get('source_ip', 'internal')
        }
        
        with self._lock:
            self.audit_log.append(audit_event)
            
        # Send to SIEM if configured
        if self._siem_client:
            self._send_to_siem(audit_event)
            
    def _send_to_siem(self, event: Dict[str, Any]):
        """Send event to SIEM system"""
        # This would integrate with Splunk, ELK, Sentinel, etc.
        pass
        
    def get_audit_log(self, start_time: Optional[datetime] = None,
                     end_time: Optional[datetime] = None,
                     event_types: Optional[List[str]] = None) -> List[Dict]:
        """Retrieve audit log entries"""
        with self._lock:
            logs = self.audit_log.copy()
            
        # Apply filters
        if start_time:
            logs = [log for log in logs 
                   if datetime.fromisoformat(log['timestamp']) >= start_time]
                   
        if end_time:
            logs = [log for log in logs 
                   if datetime.fromisoformat(log['timestamp']) <= end_time]
                   
        if event_types:
            logs = [log for log in logs if log['event_type'] in event_types]
            
        return logs
        
    # Security Posture Assessment
    def assess_security_posture(self) -> Dict[str, Any]:
        """Comprehensive security posture assessment"""
        assessment = {
            'timestamp': datetime.now().isoformat(),
            'overall_score': 0,
            'categories': {},
            'recommendations': []
        }
        
        # Assess different security categories
        categories = {
            'access_control': self._assess_access_control(),
            'encryption': self._assess_encryption(),
            'network_security': self._assess_network_security(),
            'compliance': self._assess_compliance(),
            'incident_response': self._assess_incident_response()
        }
        
        # Calculate scores and generate recommendations
        for category, results in categories.items():
            assessment['categories'][category] = results
            
            if results['score'] < 80:
                assessment['recommendations'].extend(
                    results.get('recommendations', [])
                )
                
        # Calculate overall score
        scores = [cat['score'] for cat in assessment['categories'].values()]
        assessment['overall_score'] = sum(scores) / len(scores) if scores else 0
        
        return assessment
        
    def _assess_access_control(self) -> Dict[str, Any]:
        """Assess access control security"""
        total_resources = len(self.access_controls)
        resources_with_mfa = 0
        resources_with_expiry = 0
        
        for resource, access_list in self.access_controls.items():
            for access in access_list:
                if access.conditions and access.conditions.get('require_mfa'):
                    resources_with_mfa += 1
                if access.expires_at:
                    resources_with_expiry += 1
                    
        score = 100
        recommendations = []
        
        if total_resources > 0:
            mfa_percentage = (resources_with_mfa / total_resources) * 100
            if mfa_percentage < 90:
                score -= 20
                recommendations.append("Enable MFA for all critical resources")
                
            expiry_percentage = (resources_with_expiry / total_resources) * 100
            if expiry_percentage < 50:
                score -= 10
                recommendations.append("Set expiration dates for temporary access grants")
                
        return {
            'score': max(0, score),
            'metrics': {
                'total_resources': total_resources,
                'mfa_enabled': resources_with_mfa,
                'with_expiry': resources_with_expiry
            },
            'recommendations': recommendations
        }
        
    def _assess_encryption(self) -> Dict[str, Any]:
        """Assess encryption security"""
        total_keys = len(self.encryption_keys)
        active_keys = sum(1 for k in self.encryption_keys.values() if k.status == 'active')
        keys_needing_rotation = 0
        
        for key in self.encryption_keys.values():
            if key.status == 'active':
                days_since_creation = (datetime.now() - key.created_at).days
                if days_since_creation > key.rotation_schedule.days:
                    keys_needing_rotation += 1
                    
        score = 100
        recommendations = []
        
        if keys_needing_rotation > 0:
            score -= 15
            recommendations.append(f"Rotate {keys_needing_rotation} encryption keys")
            
        if total_keys > 0 and active_keys / total_keys < 0.8:
            score -= 10
            recommendations.append("Review and clean up deprecated encryption keys")
            
        return {
            'score': max(0, score),
            'metrics': {
                'total_keys': total_keys,
                'active_keys': active_keys,
                'keys_needing_rotation': keys_needing_rotation
            },
            'recommendations': recommendations
        }
        
    def _assess_network_security(self) -> Dict[str, Any]:
        """Assess network security"""
        # This would integrate with actual network security assessments
        return {
            'score': 85,
            'metrics': {
                'public_endpoints': 0,
                'encrypted_connections': 100,
                'waf_enabled': True
            },
            'recommendations': []
        }
        
    def _assess_compliance(self) -> Dict[str, Any]:
        """Assess compliance status"""
        # Run quick compliance check
        frameworks = list(ComplianceFramework)
        compliance_results = self.run_compliance_scan(frameworks[:2])  # Sample check
        
        return {
            'score': compliance_results['overall_score'],
            'metrics': {
                'frameworks_checked': len(compliance_results['frameworks']),
                'violations': len(compliance_results['violations'])
            },
            'recommendations': [
                f"Address {len(compliance_results['violations'])} compliance violations"
            ] if compliance_results['violations'] else []
        }
        
    def _assess_incident_response(self) -> Dict[str, Any]:
        """Assess incident response readiness"""
        total_incidents = len(self.incidents)
        resolved_incidents = sum(1 for i in self.incidents.values() 
                               if i.remediation_status == 'resolved')
        critical_incidents = sum(1 for i in self.incidents.values()
                               if i.threat_level == ThreatLevel.CRITICAL)
        
        score = 100
        recommendations = []
        
        if total_incidents > 0:
            resolution_rate = (resolved_incidents / total_incidents) * 100
            if resolution_rate < 95:
                score -= 20
                recommendations.append("Improve incident resolution rate")
                
        if critical_incidents > 0:
            score -= 10
            recommendations.append(f"Review {critical_incidents} critical incidents")
            
        return {
            'score': max(0, score),
            'metrics': {
                'total_incidents': total_incidents,
                'resolved': resolved_incidents,
                'critical': critical_incidents
            },
            'recommendations': recommendations
        }
        
    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status"""
        return {
            'initialized': self._is_initialized,
            'policies': len(self.policies),
            'active_incidents': sum(1 for i in self.incidents.values() 
                                  if i.remediation_status != 'resolved'),
            'encryption_keys': {
                'total': len(self.encryption_keys),
                'active': sum(1 for k in self.encryption_keys.values() 
                            if k.status == 'active')
            },
            'access_controls': {
                'resources': len(self.access_controls),
                'total_grants': sum(len(ac) for ac in self.access_controls.values())
            },
            'audit_log_size': len(self.audit_log),
            'last_assessment': getattr(self, '_last_assessment', 'Never')
        }
        
    def export_security_report(self, report_type: str = 'full') -> Dict[str, Any]:
        """Export comprehensive security report"""
        report = {
            'generated_at': datetime.now().isoformat(),
            'report_type': report_type,
            'organization': self.config.get('organization', 'Unknown')
        }
        
        if report_type == 'full':
            report.update({
                'security_posture': self.assess_security_posture(),
                'compliance_status': self.run_compliance_scan(list(ComplianceFramework)),
                'active_incidents': [
                    inc for inc in self.incidents.values()
                    if inc.remediation_status != 'resolved'
                ],
                'policy_summary': {
                    policy_id: {
                        'name': policy.name,
                        'compliance_frameworks': [f.value for f in policy.compliance_frameworks]
                    }
                    for policy_id, policy in self.policies.items()
                }
            })
        elif report_type == 'compliance':
            report['compliance_status'] = self.run_compliance_scan(list(ComplianceFramework))
        elif report_type == 'incidents':
            report['incidents'] = list(self.incidents.values())
            
        return report