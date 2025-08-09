#!/usr/bin/env python3
"""
Schema Replication Service
Replicates database schemas with sample data and maintains referential integrity.
"""

import asyncio
import logging
import os
import random
import string
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import faker
from sqlalchemy import (
    Column, String, Integer, DateTime, Boolean, Text, Float, 
    create_engine, MetaData, Table, ForeignKey, inspect, text
)
from sqlalchemy.engine import Engine, Connection
from sqlalchemy.orm import sessionmaker, Session
import pymongo
from motor import motor_asyncio


@dataclass
class TableSchema:
    """Represents table schema information."""
    name: str
    columns: List[Dict[str, Any]]
    primary_keys: List[str]
    foreign_keys: List[Dict[str, Any]]
    indexes: List[Dict[str, Any]]
    constraints: List[Dict[str, Any]]
    row_count: int = 0
    sample_size: int = 1000
    
    def __post_init__(self):
        """Initialize computed fields."""
        self.dependencies = self._extract_dependencies()
    
    def _extract_dependencies(self) -> List[str]:
        """Extract table dependencies from foreign keys."""
        dependencies = []
        for fk in self.foreign_keys:
            ref_table = fk.get('referenced_table')
            if ref_table and ref_table != self.name:
                dependencies.append(ref_table)
        return list(set(dependencies))


@dataclass
class DatabaseSchema:
    """Complete database schema representation."""
    name: str
    database_type: str
    tables: List[TableSchema] = field(default_factory=list)
    views: List[Dict[str, Any]] = field(default_factory=list)
    procedures: List[Dict[str, Any]] = field(default_factory=list)
    functions: List[Dict[str, Any]] = field(default_factory=list)
    
    def get_table_by_name(self, table_name: str) -> Optional[TableSchema]:
        """Get table schema by name."""
        for table in self.tables:
            if table.name.lower() == table_name.lower():
                return table
        return None
    
    def get_dependency_order(self) -> List[str]:
        """Get tables ordered by dependencies (topological sort)."""
        # Simple topological sort
        visited = set()
        temp_visited = set()
        result = []
        
        def visit(table_name: str):
            if table_name in temp_visited:
                # Circular dependency - return current state
                return
            if table_name in visited:
                return
            
            temp_visited.add(table_name)
            table = self.get_table_by_name(table_name)
            if table:
                for dependency in table.dependencies:
                    visit(dependency)
            
            temp_visited.remove(table_name)
            visited.add(table_name)
            result.append(table_name)
        
        for table in self.tables:
            if table.name not in visited:
                visit(table.name)
        
        return result


class DataMasker:
    """Data masking and anonymization engine."""
    
    def __init__(self):
        self.faker = faker.Faker()
        
        # PII patterns
        self.pii_patterns = {
            'email': ['email', 'e_mail', 'mail', 'email_address'],
            'phone': ['phone', 'telephone', 'mobile', 'cell'],
            'ssn': ['ssn', 'social_security', 'social_security_number'],
            'name': ['name', 'first_name', 'last_name', 'full_name'],
            'address': ['address', 'street', 'city', 'state', 'zip'],
            'credit_card': ['credit_card', 'cc_number', 'card_number'],
            'password': ['password', 'pwd', 'pass'],
            'ip': ['ip_address', 'ip', 'remote_addr']
        }
    
    def is_sensitive_column(self, column_name: str, data_type: str) -> bool:
        """Check if column contains sensitive data."""
        column_lower = column_name.lower()
        
        for category, patterns in self.pii_patterns.items():
            for pattern in patterns:
                if pattern in column_lower:
                    return True
        
        # Check for common sensitive patterns
        sensitive_keywords = [
            'confidential', 'private', 'secret', 'secure',
            'token', 'key', 'hash', 'encrypted'
        ]
        
        return any(keyword in column_lower for keyword in sensitive_keywords)
    
    def mask_value(self, value: Any, column_name: str, data_type: str) -> Any:
        """Mask sensitive value based on column name and type."""
        if value is None:
            return None
        
        column_lower = column_name.lower()
        
        # Email masking
        if any(pattern in column_lower for pattern in self.pii_patterns['email']):
            return self.faker.email()
        
        # Name masking
        if any(pattern in column_lower for pattern in self.pii_patterns['name']):
            if 'first' in column_lower:
                return self.faker.first_name()
            elif 'last' in column_lower:
                return self.faker.last_name()
            else:
                return self.faker.name()
        
        # Phone masking
        if any(pattern in column_lower for pattern in self.pii_patterns['phone']):
            return self.faker.phone_number()
        
        # Address masking
        if any(pattern in column_lower for pattern in self.pii_patterns['address']):
            if 'street' in column_lower:
                return self.faker.street_address()
            elif 'city' in column_lower:
                return self.faker.city()
            elif 'state' in column_lower:
                return self.faker.state()
            elif 'zip' in column_lower:
                return self.faker.zipcode()
            else:
                return self.faker.address()
        
        # SSN masking
        if any(pattern in column_lower for pattern in self.pii_patterns['ssn']):
            return self.faker.ssn()
        
        # Credit card masking
        if any(pattern in column_lower for pattern in self.pii_patterns['credit_card']):
            return self.faker.credit_card_number()
        
        # Password masking
        if any(pattern in column_lower for pattern in self.pii_patterns['password']):
            return self._generate_fake_hash()
        
        # IP address masking
        if any(pattern in column_lower for pattern in self.pii_patterns['ip']):
            return self.faker.ipv4()
        
        # Generic masking based on data type
        if isinstance(value, str):
            return self._mask_string(value, column_name)
        elif isinstance(value, (int, float)):
            return self._mask_number(value, column_name)
        else:
            return value
    
    def _mask_string(self, value: str, column_name: str) -> str:
        """Generic string masking."""
        if len(value) <= 3:
            return 'X' * len(value)
        
        # Keep first and last character, mask middle
        return value[0] + 'X' * (len(value) - 2) + value[-1]
    
    def _mask_number(self, value: Union[int, float], column_name: str) -> Union[int, float]:
        """Generic number masking."""
        # Add some random variation but keep same order of magnitude
        if isinstance(value, int):
            variation = random.randint(-abs(value) // 10, abs(value) // 10)
            return max(0, value + variation)
        else:
            variation = random.uniform(-abs(value) * 0.1, abs(value) * 0.1)
            return max(0.0, value + variation)
    
    def _generate_fake_hash(self) -> str:
        """Generate fake hash string."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=32))


class SchemaReplicator:
    """
    Database schema replication service.
    
    Features:
    - Multi-database schema extraction
    - Sample data generation with referential integrity
    - Automatic data masking
    - Incremental replication
    - Progress monitoring
    """
    
    def __init__(self, source_connection: str, target_connection: str):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.source_connection = source_connection
        self.target_connection = target_connection
        
        # Data masking
        self.masker = DataMasker()
        self.mask_sensitive_data = True
        
        # Replication settings
        self.default_sample_size = 1000
        self.preserve_referential_integrity = True
        self.max_concurrent_tables = 3
        
        # Progress tracking
        self.replication_stats = {
            'tables_processed': 0,
            'rows_copied': 0,
            'start_time': None,
            'end_time': None,
            'errors': []
        }
    
    async def replicate_schema(
        self, 
        database_name: str,
        tables_to_replicate: Optional[List[str]] = None,
        sample_size: int = 1000
    ) -> Dict[str, Any]:
        """
        Replicate database schema with sample data.
        
        Args:
            database_name: Name of database to replicate
            tables_to_replicate: Specific tables to replicate (None for all)
            sample_size: Number of sample rows per table
            
        Returns:
            Replication results and statistics
        """
        self.logger.info(f"Starting schema replication for database: {database_name}")
        self.replication_stats['start_time'] = datetime.now()
        
        try:
            # 1. Extract source schema
            source_schema = await self._extract_schema(database_name, tables_to_replicate)
            self.logger.info(f"Extracted schema with {len(source_schema.tables)} tables")
            
            # 2. Create target database structure
            await self._create_target_schema(source_schema)
            
            # 3. Determine replication order
            table_order = source_schema.get_dependency_order()
            if tables_to_replicate:
                table_order = [t for t in table_order if t in tables_to_replicate]
            
            self.logger.info(f"Replication order: {table_order}")
            
            # 4. Replicate data with referential integrity
            await self._replicate_data(source_schema, table_order, sample_size)
            
            self.replication_stats['end_time'] = datetime.now()
            self.logger.info("Schema replication completed successfully")
            
            return {
                'success': True,
                'statistics': self.replication_stats,
                'tables_replicated': table_order,
                'schema_info': {
                    'table_count': len(source_schema.tables),
                    'view_count': len(source_schema.views),
                    'procedure_count': len(source_schema.procedures)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Schema replication failed: {e}")
            self.replication_stats['errors'].append(str(e))
            self.replication_stats['end_time'] = datetime.now()
            
            return {
                'success': False,
                'error': str(e),
                'statistics': self.replication_stats
            }
    
    async def _extract_schema(
        self, 
        database_name: str, 
        tables_filter: Optional[List[str]] = None
    ) -> DatabaseSchema:
        """Extract complete database schema."""
        
        if self.source_connection.startswith('mongodb://'):
            return await self._extract_mongodb_schema(database_name, tables_filter)
        else:
            return await self._extract_sql_schema(database_name, tables_filter)
    
    async def _extract_sql_schema(
        self, 
        database_name: str, 
        tables_filter: Optional[List[str]] = None
    ) -> DatabaseSchema:
        """Extract SQL database schema using SQLAlchemy."""
        
        engine = create_engine(self.source_connection)
        inspector = inspect(engine)
        
        schema = DatabaseSchema(
            name=database_name,
            database_type="sql"
        )
        
        # Get all table names
        table_names = inspector.get_table_names()
        if tables_filter:
            table_names = [t for t in table_names if t in tables_filter]
        
        # Extract each table schema
        for table_name in table_names:
            try:
                table_schema = await self._extract_table_schema(inspector, table_name)
                schema.tables.append(table_schema)
            except Exception as e:
                self.logger.warning(f"Failed to extract schema for table {table_name}: {e}")
                self.replication_stats['errors'].append(f"Schema extraction failed for {table_name}: {e}")
        
        # Extract views
        try:
            view_names = inspector.get_view_names()
            for view_name in view_names:
                view_definition = inspector.get_view_definition(view_name)
                schema.views.append({
                    'name': view_name,
                    'definition': view_definition
                })
        except Exception as e:
            self.logger.warning(f"Failed to extract views: {e}")
        
        return schema
    
    async def _extract_table_schema(self, inspector, table_name: str) -> TableSchema:
        """Extract individual table schema."""
        
        # Get columns
        columns = []
        for column in inspector.get_columns(table_name):
            columns.append({
                'name': column['name'],
                'type': str(column['type']),
                'nullable': column['nullable'],
                'default': column.get('default'),
                'primary_key': column.get('primary_key', False)
            })
        
        # Get primary keys
        primary_keys = inspector.get_pk_constraint(table_name)['constrained_columns']
        
        # Get foreign keys
        foreign_keys = []
        for fk in inspector.get_foreign_keys(table_name):
            foreign_keys.append({
                'constrained_columns': fk['constrained_columns'],
                'referenced_table': fk['referred_table'],
                'referenced_columns': fk['referred_columns']
            })
        
        # Get indexes
        indexes = []
        for index in inspector.get_indexes(table_name):
            indexes.append({
                'name': index['name'],
                'columns': index['column_names'],
                'unique': index['unique']
            })
        
        # Get row count (approximate)
        row_count = await self._get_table_row_count(table_name)
        
        return TableSchema(
            name=table_name,
            columns=columns,
            primary_keys=primary_keys,
            foreign_keys=foreign_keys,
            indexes=indexes,
            constraints=[],
            row_count=row_count
        )
    
    async def _extract_mongodb_schema(
        self, 
        database_name: str, 
        collections_filter: Optional[List[str]] = None
    ) -> DatabaseSchema:
        """Extract MongoDB schema by sampling documents."""
        
        client = motor_asyncio.AsyncIOMotorClient(self.source_connection)
        database = client[database_name]
        
        schema = DatabaseSchema(
            name=database_name,
            database_type="mongodb"
        )
        
        # Get collection names
        collection_names = await database.list_collection_names()
        if collections_filter:
            collection_names = [c for c in collection_names if c in collections_filter]
        
        # Sample documents to infer schema
        for collection_name in collection_names:
            try:
                collection = database[collection_name]
                
                # Sample documents to infer schema
                sample_docs = []
                async for doc in collection.find().limit(100):
                    sample_docs.append(doc)
                
                if sample_docs:
                    inferred_columns = self._infer_mongo_schema(sample_docs)
                    row_count = await collection.count_documents({})
                    
                    table_schema = TableSchema(
                        name=collection_name,
                        columns=inferred_columns,
                        primary_keys=['_id'],
                        foreign_keys=[],
                        indexes=[],
                        constraints=[],
                        row_count=row_count
                    )
                    
                    schema.tables.append(table_schema)
                    
            except Exception as e:
                self.logger.warning(f"Failed to extract MongoDB schema for {collection_name}: {e}")
        
        client.close()
        return schema
    
    def _infer_mongo_schema(self, documents: List[Dict]) -> List[Dict[str, Any]]:
        """Infer schema from MongoDB documents."""
        field_types = {}
        
        for doc in documents:
            for key, value in doc.items():
                if key not in field_types:
                    field_types[key] = set()
                
                field_types[key].add(type(value).__name__)
        
        columns = []
        for field_name, types in field_types.items():
            # Use most common type
            primary_type = list(types)[0] if len(types) == 1 else 'mixed'
            
            columns.append({
                'name': field_name,
                'type': primary_type,
                'nullable': True,
                'primary_key': field_name == '_id'
            })
        
        return columns
    
    async def _get_table_row_count(self, table_name: str) -> int:
        """Get approximate row count for table."""
        try:
            engine = create_engine(self.source_connection)
            with engine.connect() as conn:
                result = conn.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
                return result.scalar() or 0
        except Exception as e:
            self.logger.warning(f"Failed to get row count for {table_name}: {e}")
            return 0
    
    async def _create_target_schema(self, source_schema: DatabaseSchema) -> None:
        """Create schema structure in target database."""
        
        if self.target_connection.startswith('sqlite://'):
            await self._create_sqlite_schema(source_schema)
        else:
            await self._create_sql_schema(source_schema)
    
    async def _create_sqlite_schema(self, source_schema: DatabaseSchema) -> None:
        """Create schema in SQLite target database."""
        
        engine = create_engine(self.target_connection)
        metadata = MetaData()
        
        # Create tables in dependency order
        table_order = source_schema.get_dependency_order()
        
        for table_name in table_order:
            table_schema = source_schema.get_table_by_name(table_name)
            if not table_schema:
                continue
            
            # Define columns
            columns = []
            for col in table_schema.columns:
                column_type = self._map_column_type(col['type'])
                
                column = Column(
                    col['name'],
                    column_type,
                    primary_key=col['name'] in table_schema.primary_keys,
                    nullable=col['nullable']
                )
                columns.append(column)
            
            # Add foreign key constraints
            for fk in table_schema.foreign_keys:
                if fk['constrained_columns'] and fk['referenced_table']:
                    for i, col_name in enumerate(fk['constrained_columns']):
                        ref_col = fk['referenced_columns'][i] if i < len(fk['referenced_columns']) else fk['referenced_columns'][0]
                        
                        # Find column and add foreign key
                        for column in columns:
                            if column.name == col_name:
                                column.append_constraint(
                                    ForeignKey(f"{fk['referenced_table']}.{ref_col}")
                                )
            
            # Create table
            table = Table(table_name, metadata, *columns)
        
        # Create all tables
        metadata.create_all(engine)
        self.logger.info(f"Created {len(table_order)} tables in target database")
    
    def _map_column_type(self, source_type: str):
        """Map source column type to SQLAlchemy type."""
        source_type_lower = source_type.lower()
        
        if 'int' in source_type_lower:
            return Integer
        elif 'varchar' in source_type_lower or 'char' in source_type_lower:
            return String(255)  # Default length
        elif 'text' in source_type_lower:
            return Text
        elif 'float' in source_type_lower or 'real' in source_type_lower:
            return Float
        elif 'bool' in source_type_lower or 'bit' in source_type_lower:
            return Boolean
        elif 'date' in source_type_lower or 'time' in source_type_lower:
            return DateTime
        else:
            return String(255)  # Default fallback
    
    async def _replicate_data(
        self, 
        schema: DatabaseSchema, 
        table_order: List[str], 
        sample_size: int
    ) -> None:
        """Replicate sample data maintaining referential integrity."""
        
        # Keep track of generated primary keys for FK relationships
        pk_mapping: Dict[str, Dict[Any, Any]] = {}
        
        for table_name in table_order:
            try:
                table_schema = schema.get_table_by_name(table_name)
                if not table_schema:
                    continue
                
                self.logger.info(f"Replicating data for table: {table_name}")
                
                # Determine actual sample size
                actual_sample_size = min(sample_size, table_schema.row_count)
                if actual_sample_size == 0:
                    self.logger.info(f"Skipping empty table: {table_name}")
                    continue
                
                # Copy sample data
                rows_copied = await self._copy_table_data(
                    table_schema, 
                    actual_sample_size, 
                    pk_mapping
                )
                
                self.replication_stats['tables_processed'] += 1
                self.replication_stats['rows_copied'] += rows_copied
                
                self.logger.info(f"Copied {rows_copied} rows for table {table_name}")
                
            except Exception as e:
                error_msg = f"Failed to replicate data for table {table_name}: {e}"
                self.logger.error(error_msg)
                self.replication_stats['errors'].append(error_msg)
    
    async def _copy_table_data(
        self, 
        table_schema: TableSchema, 
        sample_size: int,
        pk_mapping: Dict[str, Dict[Any, Any]]
    ) -> int:
        """Copy sample data for individual table."""
        
        # Get sample data from source
        source_engine = create_engine(self.source_connection)
        target_engine = create_engine(self.target_connection)
        
        # Build sample query
        if sample_size >= table_schema.row_count:
            # Take all rows
            query = f"SELECT * FROM {table_schema.name}"
        else:
            # Random sample
            if 'mssql' in self.source_connection.lower():
                query = f"SELECT TOP {sample_size} * FROM {table_schema.name} ORDER BY NEWID()"
            elif 'mysql' in self.source_connection.lower():
                query = f"SELECT * FROM {table_schema.name} ORDER BY RAND() LIMIT {sample_size}"
            elif 'postgresql' in self.source_connection.lower():
                query = f"SELECT * FROM {table_schema.name} ORDER BY RANDOM() LIMIT {sample_size}"
            else:
                query = f"SELECT * FROM {table_schema.name} LIMIT {sample_size}"
        
        rows_copied = 0
        
        with source_engine.connect() as source_conn:
            with target_engine.connect() as target_conn:
                
                # Fetch source data
                result = source_conn.execute(text(query))
                rows = result.fetchall()
                
                if not rows:
                    return 0
                
                # Process and insert rows
                for row in rows:
                    try:
                        # Convert row to dictionary
                        row_dict = dict(row._mapping) if hasattr(row, '_mapping') else dict(row)
                        
                        # Apply data masking
                        if self.mask_sensitive_data:
                            row_dict = self._mask_row_data(row_dict, table_schema)
                        
                        # Handle foreign key relationships
                        row_dict = self._fix_foreign_keys(row_dict, table_schema, pk_mapping)
                        
                        # Insert row
                        columns = list(row_dict.keys())
                        values = list(row_dict.values())
                        placeholders = ', '.join(['?' for _ in values])
                        
                        insert_query = f"INSERT INTO {table_schema.name} ({', '.join(columns)}) VALUES ({placeholders})"
                        target_conn.execute(text(insert_query), values)
                        
                        # Track primary key mapping
                        for pk_col in table_schema.primary_keys:
                            if pk_col in row_dict:
                                if table_schema.name not in pk_mapping:
                                    pk_mapping[table_schema.name] = {}
                                pk_mapping[table_schema.name][row_dict[pk_col]] = row_dict[pk_col]
                        
                        rows_copied += 1
                        
                    except Exception as e:
                        self.logger.warning(f"Failed to insert row in {table_schema.name}: {e}")
                        continue
                
                # Commit transaction
                target_conn.commit()
        
        return rows_copied
    
    def _mask_row_data(self, row_dict: Dict[str, Any], table_schema: TableSchema) -> Dict[str, Any]:
        """Apply data masking to row data."""
        masked_dict = row_dict.copy()
        
        for column in table_schema.columns:
            col_name = column['name']
            if col_name in masked_dict:
                
                # Skip primary keys and foreign keys from masking
                if col_name in table_schema.primary_keys:
                    continue
                
                is_fk = any(col_name in fk['constrained_columns'] for fk in table_schema.foreign_keys)
                if is_fk:
                    continue
                
                # Apply masking if sensitive
                if self.masker.is_sensitive_column(col_name, column['type']):
                    masked_dict[col_name] = self.masker.mask_value(
                        masked_dict[col_name], 
                        col_name, 
                        column['type']
                    )
        
        return masked_dict
    
    def _fix_foreign_keys(
        self, 
        row_dict: Dict[str, Any], 
        table_schema: TableSchema,
        pk_mapping: Dict[str, Dict[Any, Any]]
    ) -> Dict[str, Any]:
        """Fix foreign key relationships in row data."""
        
        if not self.preserve_referential_integrity:
            return row_dict
        
        fixed_dict = row_dict.copy()
        
        for fk in table_schema.foreign_keys:
            ref_table = fk['referenced_table']
            
            # Check if we have primary key mapping for referenced table
            if ref_table in pk_mapping:
                ref_pk_mapping = pk_mapping[ref_table]
                
                for i, fk_col in enumerate(fk['constrained_columns']):
                    if fk_col in fixed_dict:
                        original_value = fixed_dict[fk_col]
                        
                        # Find corresponding value in referenced table
                        if original_value in ref_pk_mapping:
                            fixed_dict[fk_col] = ref_pk_mapping[original_value]
                        else:
                            # If no mapping found, use a random existing value
                            if ref_pk_mapping:
                                fixed_dict[fk_col] = random.choice(list(ref_pk_mapping.values()))
                            else:
                                # Set to None if no references exist
                                fixed_dict[fk_col] = None
        
        return fixed_dict
    
    async def get_replication_status(self) -> Dict[str, Any]:
        """Get current replication status and progress."""
        
        status = self.replication_stats.copy()
        
        # Calculate duration
        if status['start_time'] and status['end_time']:
            duration = status['end_time'] - status['start_time']
            status['duration_seconds'] = duration.total_seconds()
        elif status['start_time']:
            duration = datetime.now() - status['start_time']
            status['duration_seconds'] = duration.total_seconds()
        
        # Calculate rates
        if status.get('duration_seconds', 0) > 0:
            status['tables_per_second'] = status['tables_processed'] / status['duration_seconds']
            status['rows_per_second'] = status['rows_copied'] / status['duration_seconds']
        
        return status


# CLI interface for schema replication
async def main():
    """CLI interface for schema replication."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Database Schema Replicator")
    parser.add_argument("--source", required=True, help="Source database connection string")
    parser.add_argument("--target", required=True, help="Target database connection string")
    parser.add_argument("--database", required=True, help="Database name to replicate")
    parser.add_argument("--tables", nargs='+', help="Specific tables to replicate")
    parser.add_argument("--sample-size", type=int, default=1000, help="Sample size per table")
    parser.add_argument("--no-masking", action='store_true', help="Disable data masking")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create replicator
    replicator = SchemaReplicator(args.source, args.target)
    replicator.mask_sensitive_data = not args.no_masking
    
    # Run replication
    result = await replicator.replicate_schema(
        database_name=args.database,
        tables_to_replicate=args.tables,
        sample_size=args.sample_size
    )
    
    # Print results
    if result['success']:
        print("✅ Schema replication completed successfully!")
        print(f"📊 Tables replicated: {result['statistics']['tables_processed']}")
        print(f"📊 Rows copied: {result['statistics']['rows_copied']}")
        
        duration = result['statistics'].get('duration_seconds', 0)
        if duration:
            print(f"⏱️  Duration: {duration:.1f} seconds")
    else:
        print("❌ Schema replication failed!")
        print(f"Error: {result['error']}")
        
        if result['statistics']['errors']:
            print("\nDetailed errors:")
            for error in result['statistics']['errors']:
                print(f"  - {error}")


if __name__ == "__main__":
    asyncio.run(main())