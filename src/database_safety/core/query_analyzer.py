#!/usr/bin/env python3
"""
SQL/MongoDB Query Safety Analyzer
AST-level parsing and operation classification for bulletproof safety validation.
"""

import ast
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union

import sqlparse
from sqlparse.sql import IdentifierList, Identifier, Function, Statement
from sqlparse.tokens import Keyword, DML, DDL


class QueryType(str, Enum):
    """Types of database queries."""
    SELECT = "select"
    INSERT = "insert" 
    UPDATE = "update"
    DELETE = "delete"
    CREATE = "create"
    DROP = "drop"
    ALTER = "alter"
    TRUNCATE = "truncate"
    EXECUTE = "execute"
    CALL = "call"
    UNKNOWN = "unknown"


class SafetyLevel(str, Enum):
    """Query safety classification levels."""
    SAFE = "safe"           # Read-only operations
    MODERATE = "moderate"   # Limited write operations
    DANGEROUS = "dangerous" # Destructive operations
    CRITICAL = "critical"   # System-level changes


class DatabaseDialect(str, Enum):
    """Database SQL dialects."""
    MSSQL = "mssql"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MONGODB = "mongodb"
    FABRIC = "fabric"


@dataclass
class SafetyRule:
    """Individual safety rule configuration."""
    pattern: str
    risk_level: SafetyLevel
    description: str
    block_in_production: bool = True
    block_in_dev: bool = True
    block_in_sandbox: bool = False


@dataclass
class QueryAnalysis:
    """Comprehensive query analysis result."""
    original_query: str
    normalized_query: str
    query_type: QueryType
    operations: List[QueryType]
    safety_level: SafetyLevel
    
    # Structural analysis
    tables_accessed: List[str] = field(default_factory=list)
    columns_accessed: List[str] = field(default_factory=list) 
    functions_used: List[str] = field(default_factory=list)
    
    # Risk assessment
    risk_factors: List[str] = field(default_factory=list)
    potential_issues: List[str] = field(default_factory=list)
    
    # Pattern matching
    matched_rules: List[SafetyRule] = field(default_factory=list)
    
    # MongoDB specific
    mongodb_operations: List[str] = field(default_factory=list)
    mongodb_collections: List[str] = field(default_factory=list)


@dataclass  
class SafetyCheck:
    """Result of safety validation."""
    allowed: bool
    reason: str
    risk_level: str
    blocked_operations: List[QueryType] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


class QuerySafetyAnalyzer:
    """
    Advanced query safety analyzer with AST-level parsing.
    
    Features:
    - SQL parsing with sqlparse
    - MongoDB query analysis
    - Pattern-based risk detection
    - Whitelist/blacklist validation
    - Dialect-specific rules
    """
    
    def __init__(self, safety_rules: Optional[List[SafetyRule]] = None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.safety_rules = safety_rules or self._default_safety_rules()
        
        # Compile regex patterns for performance
        self._compiled_patterns = {}
        self._compile_patterns()
        
        # Dangerous keywords that should never be allowed
        self.dangerous_keywords = {
            'drop', 'truncate', 'delete', 'exec', 'execute', 
            'xp_cmdshell', 'sp_configure', 'openrowset', 'opendatasource',
            'bulk', 'backup', 'restore', 'shutdown', 'waitfor'
        }
        
        # System tables/schemas that should be protected
        self.system_objects = {
            'sys', 'information_schema', 'master', 'model', 'msdb', 'tempdb',
            'mysql', 'performance_schema', 'pg_catalog', 'pg_toast'
        }
    
    def _default_safety_rules(self) -> List[SafetyRule]:
        """Default set of safety rules."""
        return [
            # Critical operations
            SafetyRule(
                pattern=r'\b(drop|truncate)\s+(table|database|schema)',
                risk_level=SafetyLevel.CRITICAL,
                description="DROP/TRUNCATE operations are destructive",
                block_in_sandbox=True  # Even sandbox shouldn't allow DROP
            ),
            
            # Dangerous system calls
            SafetyRule(
                pattern=r'\bxp_cmdshell\b',
                risk_level=SafetyLevel.CRITICAL,
                description="Command execution via xp_cmdshell",
                block_in_sandbox=True
            ),
            
            # Bulk operations
            SafetyRule(
                pattern=r'\b(bulk\s+insert|openrowset|opendatasource)\b',
                risk_level=SafetyLevel.DANGEROUS,
                description="Bulk data operations can affect performance"
            ),
            
            # DELETE without WHERE
            SafetyRule(
                pattern=r'\bdelete\s+from\s+\w+\s*(?!where)',
                risk_level=SafetyLevel.DANGEROUS,
                description="DELETE without WHERE clause"
            ),
            
            # UPDATE without WHERE  
            SafetyRule(
                pattern=r'\bupdate\s+\w+\s+set\s+.*?(?!where)',
                risk_level=SafetyLevel.DANGEROUS,
                description="UPDATE without WHERE clause"
            ),
            
            # System table access
            SafetyRule(
                pattern=r'\b(sys\.|information_schema\.|master\.|msdb\.)',
                risk_level=SafetyLevel.MODERATE,
                description="System table/schema access",
                block_in_production=True,
                block_in_dev=False,
                block_in_sandbox=False
            )
        ]
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for performance."""
        for rule in self.safety_rules:
            try:
                self._compiled_patterns[rule.pattern] = re.compile(
                    rule.pattern, 
                    re.IGNORECASE | re.MULTILINE
                )
            except re.error as e:
                self.logger.warning(f"Invalid regex pattern: {rule.pattern} - {e}")
    
    async def analyze_query(
        self, 
        query: str, 
        database_type: str,
        dialect: DatabaseDialect = DatabaseDialect.MSSQL
    ) -> QueryAnalysis:
        """
        Comprehensive query analysis.
        
        Args:
            query: SQL or MongoDB query string
            database_type: Type of database (mssql, mongodb, etc.)
            dialect: SQL dialect for parsing
            
        Returns:
            QueryAnalysis with full safety assessment
        """
        if database_type.lower() == "mongodb":
            return await self._analyze_mongodb_query(query)
        else:
            return await self._analyze_sql_query(query, dialect)
    
    async def _analyze_sql_query(
        self, 
        query: str, 
        dialect: DatabaseDialect
    ) -> QueryAnalysis:
        """Analyze SQL query with sqlparse."""
        
        # Normalize query
        normalized_query = self._normalize_sql_query(query)
        
        # Parse with sqlparse
        try:
            parsed = sqlparse.parse(normalized_query)[0]
        except Exception as e:
            self.logger.warning(f"SQL parsing failed: {e}")
            # Fallback to basic analysis
            return self._basic_sql_analysis(query, normalized_query)
        
        # Extract query components
        query_type = self._extract_query_type(parsed)
        operations = self._extract_operations(parsed)
        tables = self._extract_tables(parsed)
        columns = self._extract_columns(parsed)
        functions = self._extract_functions(parsed)
        
        # Risk assessment
        safety_level = self._assess_safety_level(operations, query_type)
        risk_factors = self._identify_risk_factors(normalized_query, operations)
        matched_rules = self._match_safety_rules(normalized_query)
        
        return QueryAnalysis(
            original_query=query,
            normalized_query=normalized_query,
            query_type=query_type,
            operations=operations,
            safety_level=safety_level,
            tables_accessed=tables,
            columns_accessed=columns,
            functions_used=functions,
            risk_factors=risk_factors,
            matched_rules=matched_rules,
            potential_issues=self._identify_potential_issues(
                operations, tables, normalized_query
            )
        )
    
    async def _analyze_mongodb_query(self, query: str) -> QueryAnalysis:
        """Analyze MongoDB query (JSON/JavaScript format)."""
        
        # Try to parse as JSON/JavaScript
        normalized_query = query.strip()
        
        # Extract MongoDB operations
        operations = self._extract_mongodb_operations(normalized_query)
        collections = self._extract_mongodb_collections(normalized_query)
        
        # Convert to QueryType equivalents
        query_operations = []
        for op in operations:
            if op in ['find', 'findOne', 'aggregate', 'count']:
                query_operations.append(QueryType.SELECT)
            elif op in ['insertOne', 'insertMany']:
                query_operations.append(QueryType.INSERT)
            elif op in ['updateOne', 'updateMany', 'replaceOne']:
                query_operations.append(QueryType.UPDATE)
            elif op in ['deleteOne', 'deleteMany']:
                query_operations.append(QueryType.DELETE)
            elif op in ['createIndex', 'createCollection']:
                query_operations.append(QueryType.CREATE)
            elif op in ['drop', 'dropIndex']:
                query_operations.append(QueryType.DROP)
        
        primary_type = query_operations[0] if query_operations else QueryType.UNKNOWN
        safety_level = self._assess_safety_level(query_operations, primary_type)
        
        return QueryAnalysis(
            original_query=query,
            normalized_query=normalized_query,
            query_type=primary_type,
            operations=query_operations,
            safety_level=safety_level,
            mongodb_operations=operations,
            mongodb_collections=collections,
            risk_factors=self._identify_mongodb_risks(operations, normalized_query),
            matched_rules=self._match_safety_rules(normalized_query)
        )
    
    def _normalize_sql_query(self, query: str) -> str:
        """Normalize SQL query for analysis."""
        # Remove comments
        query = re.sub(r'--.*$', '', query, flags=re.MULTILINE)
        query = re.sub(r'/\*.*?\*/', '', query, flags=re.DOTALL)
        
        # Normalize whitespace
        query = re.sub(r'\s+', ' ', query.strip())
        
        return query
    
    def _basic_sql_analysis(self, original: str, normalized: str) -> QueryAnalysis:
        """Fallback analysis when parsing fails."""
        
        # Basic pattern matching
        query_type = self._detect_query_type_pattern(normalized)
        operations = [query_type] if query_type != QueryType.UNKNOWN else []
        
        return QueryAnalysis(
            original_query=original,
            normalized_query=normalized,
            query_type=query_type,
            operations=operations,
            safety_level=self._assess_safety_level(operations, query_type),
            risk_factors=self._identify_risk_factors(normalized, operations),
            matched_rules=self._match_safety_rules(normalized)
        )
    
    def _extract_query_type(self, parsed: Statement) -> QueryType:
        """Extract primary query type from parsed SQL."""
        
        first_token = None
        for token in parsed.flatten():
            if token.ttype is Keyword and not token.is_whitespace:
                first_token = token.value.upper()
                break
        
        if not first_token:
            return QueryType.UNKNOWN
        
        # Map SQL keywords to query types
        keyword_mapping = {
            'SELECT': QueryType.SELECT,
            'INSERT': QueryType.INSERT, 
            'UPDATE': QueryType.UPDATE,
            'DELETE': QueryType.DELETE,
            'CREATE': QueryType.CREATE,
            'DROP': QueryType.DROP,
            'ALTER': QueryType.ALTER,
            'TRUNCATE': QueryType.TRUNCATE,
            'EXECUTE': QueryType.EXECUTE,
            'EXEC': QueryType.EXECUTE,
            'CALL': QueryType.CALL
        }
        
        return keyword_mapping.get(first_token, QueryType.UNKNOWN)
    
    def _extract_operations(self, parsed: Statement) -> List[QueryType]:
        """Extract all operations from parsed SQL."""
        operations = []
        
        for token in parsed.flatten():
            if token.ttype in (Keyword.DML, Keyword.DDL):
                keyword = token.value.upper()
                if keyword in ['SELECT']:
                    operations.append(QueryType.SELECT)
                elif keyword in ['INSERT']:
                    operations.append(QueryType.INSERT)
                elif keyword in ['UPDATE']:
                    operations.append(QueryType.UPDATE)
                elif keyword in ['DELETE']:
                    operations.append(QueryType.DELETE)
                elif keyword in ['CREATE']:
                    operations.append(QueryType.CREATE)
                elif keyword in ['DROP']:
                    operations.append(QueryType.DROP)
                elif keyword in ['ALTER']:
                    operations.append(QueryType.ALTER)
                elif keyword in ['TRUNCATE']:
                    operations.append(QueryType.TRUNCATE)
        
        return operations or [self._extract_query_type(parsed)]
    
    def _extract_tables(self, parsed: Statement) -> List[str]:
        """Extract table names from parsed SQL."""
        tables = []
        
        # This is a simplified extraction - real implementation would be more robust
        for token in parsed.flatten():
            if isinstance(token, Identifier):
                tables.append(str(token))
            elif isinstance(token, IdentifierList):
                for identifier in token.get_identifiers():
                    tables.append(str(identifier))
        
        return list(set(tables))
    
    def _extract_columns(self, parsed: Statement) -> List[str]:
        """Extract column names from parsed SQL."""
        columns = []
        
        # Simplified column extraction
        # Real implementation would need context-aware parsing
        
        return columns
    
    def _extract_functions(self, parsed: Statement) -> List[str]:
        """Extract function calls from parsed SQL."""
        functions = []
        
        for token in parsed.flatten():
            if isinstance(token, Function):
                functions.append(str(token))
        
        return functions
    
    def _detect_query_type_pattern(self, query: str) -> QueryType:
        """Detect query type using regex patterns."""
        query_upper = query.upper()
        
        if query_upper.startswith('SELECT'):
            return QueryType.SELECT
        elif query_upper.startswith('INSERT'):
            return QueryType.INSERT
        elif query_upper.startswith('UPDATE'):
            return QueryType.UPDATE
        elif query_upper.startswith('DELETE'):
            return QueryType.DELETE
        elif query_upper.startswith('CREATE'):
            return QueryType.CREATE
        elif query_upper.startswith('DROP'):
            return QueryType.DROP
        elif query_upper.startswith('ALTER'):
            return QueryType.ALTER
        elif query_upper.startswith('TRUNCATE'):
            return QueryType.TRUNCATE
        elif query_upper.startswith(('EXECUTE', 'EXEC')):
            return QueryType.EXECUTE
        else:
            return QueryType.UNKNOWN
    
    def _assess_safety_level(
        self, 
        operations: List[QueryType], 
        primary_type: QueryType
    ) -> SafetyLevel:
        """Assess overall safety level of query."""
        
        # Critical operations
        if any(op in [QueryType.DROP, QueryType.TRUNCATE] for op in operations):
            return SafetyLevel.CRITICAL
        
        # Dangerous operations  
        if any(op in [QueryType.DELETE, QueryType.EXECUTE] for op in operations):
            return SafetyLevel.DANGEROUS
        
        # Moderate operations
        if any(op in [QueryType.INSERT, QueryType.UPDATE, QueryType.CREATE, QueryType.ALTER] for op in operations):
            return SafetyLevel.MODERATE
        
        # Safe operations
        if primary_type == QueryType.SELECT:
            return SafetyLevel.SAFE
        
        return SafetyLevel.MODERATE
    
    def _identify_risk_factors(
        self, 
        query: str, 
        operations: List[QueryType]
    ) -> List[str]:
        """Identify specific risk factors in query."""
        risks = []
        query_lower = query.lower()
        
        # Check for dangerous keywords
        for keyword in self.dangerous_keywords:
            if keyword in query_lower:
                risks.append(f"Contains dangerous keyword: {keyword}")
        
        # Check for system object access
        for obj in self.system_objects:
            if obj in query_lower:
                risks.append(f"Accesses system object: {obj}")
        
        # Check for missing WHERE clauses
        if QueryType.DELETE in operations and 'where' not in query_lower:
            risks.append("DELETE without WHERE clause")
        
        if QueryType.UPDATE in operations and 'where' not in query_lower:
            risks.append("UPDATE without WHERE clause")
        
        # Check for wildcards
        if re.search(r'select\s+\*\s+from', query_lower):
            risks.append("SELECT * may return large dataset")
        
        return risks
    
    def _match_safety_rules(self, query: str) -> List[SafetyRule]:
        """Match query against configured safety rules."""
        matched_rules = []
        
        for rule in self.safety_rules:
            pattern = self._compiled_patterns.get(rule.pattern)
            if pattern and pattern.search(query):
                matched_rules.append(rule)
        
        return matched_rules
    
    def _identify_potential_issues(
        self, 
        operations: List[QueryType], 
        tables: List[str], 
        query: str
    ) -> List[str]:
        """Identify potential issues with query."""
        issues = []
        
        # Performance issues
        if 'order by' in query.lower() and 'limit' not in query.lower():
            issues.append("ORDER BY without LIMIT may be slow")
        
        if len(tables) > 5:
            issues.append("Query accesses many tables - potential performance impact")
        
        # Security issues
        if re.search(r"'.*'", query):
            issues.append("String literals present - check for SQL injection")
        
        return issues
    
    def _extract_mongodb_operations(self, query: str) -> List[str]:
        """Extract MongoDB operations from query string."""
        operations = []
        
        # Common MongoDB operations
        mongo_ops = [
            'find', 'findOne', 'aggregate', 'count', 'distinct',
            'insertOne', 'insertMany', 'updateOne', 'updateMany',
            'deleteOne', 'deleteMany', 'replaceOne',
            'createIndex', 'dropIndex', 'drop', 'createCollection'
        ]
        
        for op in mongo_ops:
            if f'.{op}(' in query:
                operations.append(op)
        
        return operations
    
    def _extract_mongodb_collections(self, query: str) -> List[str]:
        """Extract collection names from MongoDB query."""
        collections = []
        
        # Simple pattern matching for db.collection.operation
        matches = re.findall(r'db\.(\w+)\.', query)
        collections.extend(matches)
        
        return list(set(collections))
    
    def _identify_mongodb_risks(
        self, 
        operations: List[str], 
        query: str
    ) -> List[str]:
        """Identify MongoDB-specific risk factors."""
        risks = []
        
        # Dangerous operations
        if 'drop' in operations:
            risks.append("DROP operation can delete entire collection")
        
        if any(op.startswith('delete') for op in operations):
            if '$where' not in query and 'deleteMany' in operations:
                risks.append("deleteMany without specific filter")
        
        # Performance risks
        if 'find' in operations and 'limit(' not in query:
            risks.append("find() without limit may return large dataset")
        
        return risks


# Utility functions for common operations
def is_query_safe(analysis: QueryAnalysis, environment: str = "production") -> bool:
    """Check if query is safe for given environment."""
    if environment == "production":
        return analysis.safety_level in [SafetyLevel.SAFE]
    elif environment == "dev":
        return analysis.safety_level in [SafetyLevel.SAFE, SafetyLevel.MODERATE]
    else:  # sandbox
        return analysis.safety_level != SafetyLevel.CRITICAL


def get_blocked_operations(analysis: QueryAnalysis, environment: str) -> List[QueryType]:
    """Get list of operations that should be blocked."""
    blocked = []
    
    for rule in analysis.matched_rules:
        should_block = False
        if environment == "production" and rule.block_in_production:
            should_block = True
        elif environment == "dev" and rule.block_in_dev:
            should_block = True
        elif environment == "sandbox" and rule.block_in_sandbox:
            should_block = True
        
        if should_block:
            blocked.extend(analysis.operations)
    
    return list(set(blocked))