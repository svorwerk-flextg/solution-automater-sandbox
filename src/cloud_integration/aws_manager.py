"""
AWS Services Manager

Provides secure access to AWS services:
- S3 (backup and artifact storage)
- RDS MySQL databases
- EC2 instances (MongoDB clusters)
- CloudFront CDN
- IAM and security management
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from dataclasses import dataclass
from enum import Enum
import pymongo
import mysql.connector
from mysql.connector import pooling
import pandas as pd
from contextlib import contextmanager
import asyncio
import aioboto3
from concurrent.futures import ThreadPoolExecutor
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


class AWSService(Enum):
    """AWS service types"""
    S3 = "s3"
    RDS = "rds"
    EC2 = "ec2"
    CLOUDFRONT = "cloudfront"
    IAM = "iam"
    CLOUDWATCH = "cloudwatch"
    VPC = "vpc"


@dataclass
class AWSConfig:
    """Configuration for AWS services"""
    region: str = "us-east-1"
    profile: Optional[str] = None
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    session_token: Optional[str] = None
    s3_backup_bucket: str = "solution-automater-backups"
    s3_artifact_bucket: str = "solution-automater-artifacts"
    rds_connection_pools: Dict[str, Dict] = None
    mongodb_clusters: Dict[str, List[str]] = None
    encryption_key: Optional[str] = None
    enable_encryption: bool = True
    max_pool_connections: int = 50
    connection_timeout: int = 30
    retry_attempts: int = 3
    enable_cost_tracking: bool = True


@dataclass
class S3BackupConfig:
    """Configuration for S3 backup operations"""
    bucket: str
    prefix: str
    lifecycle_days: int = 30
    glacier_days: int = 90
    delete_days: int = 365
    enable_versioning: bool = True
    enable_encryption: bool = True
    storage_class: str = "STANDARD_IA"
    enable_replication: bool = False
    replication_bucket: Optional[str] = None


@dataclass
class RDSConnectionInfo:
    """RDS database connection information"""
    identifier: str
    endpoint: str
    port: int
    database: str
    username: str
    password: Optional[str] = None
    vpc_security_groups: List[str] = None
    ssl_enabled: bool = True
    read_replicas: List[str] = None


class AWSServicesManager:
    """Comprehensive AWS services manager with security and monitoring"""
    
    def __init__(self, config: AWSConfig):
        self.config = config
        self._session = None
        self._clients = {}
        self._rds_pools = {}
        self._mongodb_connections = {}
        self._encryption_key = None
        self._executor = ThreadPoolExecutor(max_workers=10)
        self._is_initialized = False
        
    def initialize(self):
        """Initialize AWS services manager"""
        if self._is_initialized:
            return
            
        try:
            # Set up AWS session
            self._setup_aws_session()
            
            # Initialize encryption if enabled
            if self.config.enable_encryption:
                self._setup_encryption()
                
            # Initialize service clients
            self._initialize_clients()
            
            # Set up RDS connection pools
            if self.config.rds_connection_pools:
                self._setup_rds_pools()
                
            # Set up MongoDB connections
            if self.config.mongodb_clusters:
                self._setup_mongodb_connections()
                
            self._is_initialized = True
            logger.info("AWS services manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize AWS services manager: {e}")
            raise
            
    def _setup_aws_session(self):
        """Set up AWS session with credentials"""
        session_config = {}
        
        if self.config.profile:
            session_config['profile_name'] = self.config.profile
        elif self.config.access_key_id and self.config.secret_access_key:
            session_config['aws_access_key_id'] = self.config.access_key_id
            session_config['aws_secret_access_key'] = self.config.secret_access_key
            if self.config.session_token:
                session_config['aws_session_token'] = self.config.session_token
                
        session_config['region_name'] = self.config.region
        
        self._session = boto3.Session(**session_config)
        
    def _setup_encryption(self):
        """Set up encryption for sensitive data"""
        if self.config.encryption_key:
            # Use provided key
            self._encryption_key = self.config.encryption_key.encode()
        else:
            # Generate a new key
            self._encryption_key = Fernet.generate_key()
            
        self._cipher = Fernet(self._encryption_key)
        
    def _initialize_clients(self):
        """Initialize AWS service clients"""
        services = [
            AWSService.S3, AWSService.RDS, AWSService.EC2,
            AWSService.CLOUDFRONT, AWSService.IAM, AWSService.CLOUDWATCH,
            AWSService.VPC
        ]
        
        for service in services:
            self._clients[service.value] = self._session.client(
                service.value,
                config=boto3.session.Config(
                    max_pool_connections=self.config.max_pool_connections,
                    retries={'max_attempts': self.config.retry_attempts}
                )
            )
            
    def _get_client(self, service: AWSService):
        """Get AWS service client"""
        return self._clients.get(service.value)
        
    # S3 Operations
    def create_backup(self, data: Any, key: str, metadata: Optional[Dict] = None) -> str:
        """Create encrypted backup in S3"""
        try:
            s3_client = self._get_client(AWSService.S3)
            
            # Serialize data
            if isinstance(data, pd.DataFrame):
                serialized = data.to_json()
            elif isinstance(data, dict) or isinstance(data, list):
                serialized = json.dumps(data)
            else:
                serialized = str(data)
                
            # Encrypt if enabled
            if self.config.enable_encryption:
                serialized = self._cipher.encrypt(serialized.encode()).decode()
                
            # Add metadata
            if metadata is None:
                metadata = {}
                
            metadata.update({
                'timestamp': datetime.now().isoformat(),
                'encrypted': str(self.config.enable_encryption),
                'source': 'solution-automater-sandbox'
            })
            
            # Upload to S3
            response = s3_client.put_object(
                Bucket=self.config.s3_backup_bucket,
                Key=key,
                Body=serialized,
                Metadata=metadata,
                ServerSideEncryption='AES256',
                StorageClass='STANDARD_IA'
            )
            
            logger.info(f"Backup created: s3://{self.config.s3_backup_bucket}/{key}")
            return response['ETag']
            
        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            raise
            
    def restore_backup(self, key: str) -> Any:
        """Restore encrypted backup from S3"""
        try:
            s3_client = self._get_client(AWSService.S3)
            
            # Download from S3
            response = s3_client.get_object(
                Bucket=self.config.s3_backup_bucket,
                Key=key
            )
            
            data = response['Body'].read().decode()
            metadata = response.get('Metadata', {})
            
            # Decrypt if encrypted
            if metadata.get('encrypted') == 'True' and self.config.enable_encryption:
                data = self._cipher.decrypt(data.encode()).decode()
                
            # Deserialize based on content
            try:
                return json.loads(data)
            except:
                return data
                
        except Exception as e:
            logger.error(f"Failed to restore backup: {e}")
            raise
            
    def setup_s3_lifecycle(self, config: S3BackupConfig):
        """Set up S3 lifecycle policies for backup management"""
        try:
            s3_client = self._get_client(AWSService.S3)
            
            # Enable versioning if requested
            if config.enable_versioning:
                s3_client.put_bucket_versioning(
                    Bucket=config.bucket,
                    VersioningConfiguration={'Status': 'Enabled'}
                )
                
            # Create lifecycle policy
            lifecycle_policy = {
                'Rules': [
                    {
                        'ID': 'backup-lifecycle',
                        'Status': 'Enabled',
                        'Prefix': config.prefix,
                        'Transitions': [
                            {
                                'Days': config.lifecycle_days,
                                'StorageClass': config.storage_class
                            },
                            {
                                'Days': config.glacier_days,
                                'StorageClass': 'GLACIER'
                            }
                        ],
                        'Expiration': {
                            'Days': config.delete_days
                        }
                    }
                ]
            }
            
            s3_client.put_bucket_lifecycle_configuration(
                Bucket=config.bucket,
                LifecycleConfiguration=lifecycle_policy
            )
            
            logger.info(f"S3 lifecycle policy configured for {config.bucket}")
            
        except Exception as e:
            logger.error(f"Failed to setup S3 lifecycle: {e}")
            raise
            
    # RDS Operations
    def _setup_rds_pools(self):
        """Set up RDS connection pools"""
        for pool_name, pool_config in self.config.rds_connection_pools.items():
            try:
                # Create connection pool
                pool = mysql.connector.pooling.MySQLConnectionPool(
                    pool_name=pool_name,
                    pool_size=pool_config.get('pool_size', 5),
                    host=pool_config['host'],
                    port=pool_config.get('port', 3306),
                    user=pool_config['user'],
                    password=pool_config['password'],
                    database=pool_config['database'],
                    ssl_ca=pool_config.get('ssl_ca'),
                    ssl_verify_cert=pool_config.get('ssl_verify_cert', True),
                    autocommit=pool_config.get('autocommit', True),
                    connection_timeout=self.config.connection_timeout
                )
                
                self._rds_pools[pool_name] = pool
                logger.info(f"RDS connection pool '{pool_name}' created")
                
            except Exception as e:
                logger.error(f"Failed to create RDS pool '{pool_name}': {e}")
                
    @contextmanager
    def get_rds_connection(self, pool_name: str):
        """Get RDS connection from pool"""
        if pool_name not in self._rds_pools:
            raise ValueError(f"RDS pool '{pool_name}' not found")
            
        conn = self._rds_pools[pool_name].get_connection()
        try:
            yield conn
        finally:
            conn.close()
            
    def execute_rds_query(self, pool_name: str, query: str, 
                         params: Optional[Tuple] = None) -> pd.DataFrame:
        """Execute query on RDS database"""
        with self.get_rds_connection(pool_name) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(query, params)
            
            if cursor.description:
                # SELECT query - return results
                results = cursor.fetchall()
                return pd.DataFrame(results)
            else:
                # INSERT/UPDATE/DELETE - return affected rows
                conn.commit()
                return pd.DataFrame({'affected_rows': [cursor.rowcount]})
                
    def discover_rds_instances(self) -> List[RDSConnectionInfo]:
        """Discover all RDS instances in the region"""
        try:
            rds_client = self._get_client(AWSService.RDS)
            
            response = rds_client.describe_db_instances()
            instances = []
            
            for db in response['DBInstances']:
                instance = RDSConnectionInfo(
                    identifier=db['DBInstanceIdentifier'],
                    endpoint=db['Endpoint']['Address'],
                    port=db['Endpoint']['Port'],
                    database=db.get('DBName', ''),
                    username=db['MasterUsername'],
                    vpc_security_groups=[sg['VpcSecurityGroupId'] 
                                       for sg in db['VpcSecurityGroups']],
                    ssl_enabled=db.get('StorageEncrypted', False),
                    read_replicas=db.get('ReadReplicaDBInstanceIdentifiers', [])
                )
                instances.append(instance)
                
            return instances
            
        except Exception as e:
            logger.error(f"Failed to discover RDS instances: {e}")
            return []
            
    # EC2 MongoDB Operations
    def _setup_mongodb_connections(self):
        """Set up MongoDB connections to EC2 clusters"""
        for cluster_name, nodes in self.config.mongodb_clusters.items():
            try:
                # Build connection string
                connection_string = f"mongodb://{','.join(nodes)}/admin?replicaSet={cluster_name}"
                
                # Create MongoDB client
                client = pymongo.MongoClient(
                    connection_string,
                    serverSelectionTimeoutMS=self.config.connection_timeout * 1000,
                    connectTimeoutMS=self.config.connection_timeout * 1000,
                    maxPoolSize=self.config.max_pool_connections
                )
                
                # Test connection
                client.admin.command('ping')
                
                self._mongodb_connections[cluster_name] = client
                logger.info(f"MongoDB cluster '{cluster_name}' connected")
                
            except Exception as e:
                logger.error(f"Failed to connect to MongoDB cluster '{cluster_name}': {e}")
                
    def get_mongodb_client(self, cluster_name: str) -> pymongo.MongoClient:
        """Get MongoDB client for a specific cluster"""
        if cluster_name not in self._mongodb_connections:
            raise ValueError(f"MongoDB cluster '{cluster_name}' not found")
            
        return self._mongodb_connections[cluster_name]
        
    def discover_ec2_mongodb(self) -> Dict[str, List[str]]:
        """Discover MongoDB instances running on EC2"""
        try:
            ec2_client = self._get_client(AWSService.EC2)
            
            # Find instances with MongoDB tag
            response = ec2_client.describe_instances(
                Filters=[
                    {'Name': 'tag:service', 'Values': ['mongodb']},
                    {'Name': 'instance-state-name', 'Values': ['running']}
                ]
            )
            
            clusters = {}
            
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    # Get cluster name from tags
                    cluster_name = None
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'cluster':
                            cluster_name = tag['Value']
                            break
                            
                    if cluster_name:
                        if cluster_name not in clusters:
                            clusters[cluster_name] = []
                            
                        # Use private IP for internal connectivity
                        clusters[cluster_name].append(
                            f"{instance['PrivateIpAddress']}:27017"
                        )
                        
            return clusters
            
        except Exception as e:
            logger.error(f"Failed to discover EC2 MongoDB instances: {e}")
            return {}
            
    # Security and Monitoring
    def get_security_groups(self, vpc_id: Optional[str] = None) -> List[Dict]:
        """Get security groups configuration"""
        try:
            ec2_client = self._get_client(AWSService.EC2)
            
            filters = []
            if vpc_id:
                filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})
                
            response = ec2_client.describe_security_groups(Filters=filters)
            
            security_groups = []
            for sg in response['SecurityGroups']:
                security_groups.append({
                    'id': sg['GroupId'],
                    'name': sg['GroupName'],
                    'description': sg['Description'],
                    'vpc_id': sg['VpcId'],
                    'ingress_rules': sg['IpPermissions'],
                    'egress_rules': sg['IpPermissionsEgress']
                })
                
            return security_groups
            
        except Exception as e:
            logger.error(f"Failed to get security groups: {e}")
            return []
            
    def create_security_group(self, name: str, description: str, 
                            vpc_id: str, rules: List[Dict]) -> str:
        """Create a new security group with rules"""
        try:
            ec2_client = self._get_client(AWSService.EC2)
            
            # Create security group
            response = ec2_client.create_security_group(
                GroupName=name,
                Description=description,
                VpcId=vpc_id
            )
            
            group_id = response['GroupId']
            
            # Add ingress rules
            if rules:
                ec2_client.authorize_security_group_ingress(
                    GroupId=group_id,
                    IpPermissions=rules
                )
                
            logger.info(f"Security group '{name}' created with ID: {group_id}")
            return group_id
            
        except Exception as e:
            logger.error(f"Failed to create security group: {e}")
            raise
            
    def get_cost_metrics(self, start_date: datetime, end_date: datetime,
                        granularity: str = 'DAILY') -> pd.DataFrame:
        """Get cost metrics for AWS resources"""
        if not self.config.enable_cost_tracking:
            return pd.DataFrame()
            
        try:
            ce_client = self._session.client('ce')
            
            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date.strftime('%Y-%m-%d'),
                    'End': end_date.strftime('%Y-%m-%d')
                },
                Granularity=granularity,
                Metrics=['UnblendedCost', 'UsageQuantity'],
                GroupBy=[
                    {'Type': 'DIMENSION', 'Key': 'SERVICE'},
                    {'Type': 'TAG', 'Key': 'project'}
                ]
            )
            
            # Convert to DataFrame
            rows = []
            for result in response['ResultsByTime']:
                date = result['TimePeriod']['Start']
                for group in result['Groups']:
                    service = group['Keys'][0]
                    project = group['Keys'][1] if len(group['Keys']) > 1 else 'untagged'
                    
                    rows.append({
                        'date': date,
                        'service': service,
                        'project': project,
                        'cost': float(group['Metrics']['UnblendedCost']['Amount']),
                        'usage': float(group['Metrics']['UsageQuantity']['Amount'])
                                if 'UsageQuantity' in group['Metrics'] else 0
                    })
                    
            return pd.DataFrame(rows)
            
        except Exception as e:
            logger.error(f"Failed to get cost metrics: {e}")
            return pd.DataFrame()
            
    # CloudWatch Monitoring
    def put_metric(self, namespace: str, metric_name: str, 
                   value: float, unit: str = 'Count',
                   dimensions: Optional[List[Dict]] = None):
        """Put custom metric to CloudWatch"""
        try:
            cw_client = self._get_client(AWSService.CLOUDWATCH)
            
            metric_data = {
                'MetricName': metric_name,
                'Value': value,
                'Unit': unit,
                'Timestamp': datetime.now()
            }
            
            if dimensions:
                metric_data['Dimensions'] = dimensions
                
            cw_client.put_metric_data(
                Namespace=namespace,
                MetricData=[metric_data]
            )
            
        except Exception as e:
            logger.error(f"Failed to put metric: {e}")
            
    def create_alarm(self, alarm_name: str, metric_name: str,
                    namespace: str, threshold: float,
                    comparison_operator: str = 'GreaterThanThreshold',
                    evaluation_periods: int = 1,
                    period: int = 300,
                    actions: Optional[List[str]] = None) -> bool:
        """Create CloudWatch alarm"""
        try:
            cw_client = self._get_client(AWSService.CLOUDWATCH)
            
            cw_client.put_metric_alarm(
                AlarmName=alarm_name,
                ComparisonOperator=comparison_operator,
                EvaluationPeriods=evaluation_periods,
                MetricName=metric_name,
                Namespace=namespace,
                Period=period,
                Statistic='Average',
                Threshold=threshold,
                ActionsEnabled=True,
                AlarmActions=actions or [],
                AlarmDescription=f'Alarm for {metric_name}'
            )
            
            logger.info(f"CloudWatch alarm '{alarm_name}' created")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create alarm: {e}")
            return False
            
    # Async operations
    async def upload_files_async(self, files: List[Tuple[str, str]], 
                               bucket: str) -> List[str]:
        """Upload multiple files to S3 asynchronously"""
        async with aioboto3.Session().client('s3') as s3:
            tasks = []
            
            for local_path, s3_key in files:
                task = s3.upload_file(local_path, bucket, s3_key)
                tasks.append(task)
                
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            uploaded = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Failed to upload {files[i][0]}: {result}")
                else:
                    uploaded.append(files[i][1])
                    
            return uploaded
            
    def get_service_status(self) -> Dict[str, Any]:
        """Get status of all AWS services"""
        status = {
            'initialized': self._is_initialized,
            'region': self.config.region,
            'services': {},
            'last_check': datetime.now().isoformat()
        }
        
        if self._is_initialized:
            # Check S3
            try:
                s3_client = self._get_client(AWSService.S3)
                s3_client.head_bucket(Bucket=self.config.s3_backup_bucket)
                status['services']['s3'] = 'healthy'
            except:
                status['services']['s3'] = 'error'
                
            # Check RDS pools
            status['services']['rds_pools'] = {}
            for pool_name in self._rds_pools:
                try:
                    with self.get_rds_connection(pool_name) as conn:
                        cursor = conn.cursor()
                        cursor.execute("SELECT 1")
                        cursor.fetchone()
                    status['services']['rds_pools'][pool_name] = 'healthy'
                except:
                    status['services']['rds_pools'][pool_name] = 'error'
                    
            # Check MongoDB
            status['services']['mongodb_clusters'] = {}
            for cluster_name, client in self._mongodb_connections.items():
                try:
                    client.admin.command('ping')
                    status['services']['mongodb_clusters'][cluster_name] = 'healthy'
                except:
                    status['services']['mongodb_clusters'][cluster_name] = 'error'
                    
        return status
        
    def close(self):
        """Close all connections and clean up resources"""
        # Close RDS pools
        for pool in self._rds_pools.values():
            try:
                pool._remove_connections()
            except:
                pass
                
        # Close MongoDB connections
        for client in self._mongodb_connections.values():
            try:
                client.close()
            except:
                pass
                
        # Shutdown executor
        self._executor.shutdown(wait=True)
        
        self._is_initialized = False
        logger.info("AWS services manager closed")