"""
Cloud Integration Module for Solution-Automater-Sandbox

This module provides secure, unified access to multiple cloud platforms:
- Microsoft Fabric (Lakehouse, Delta Tables, Spark SQL)
- AWS Services (S3, RDS, EC2, CloudFront)
- Azure Services (integrated with Fabric)
- MongoDB clusters on EC2

Features:
- Unified authentication and credential management
- Cross-cloud data synchronization
- Security and compliance management
- Resource monitoring and cost optimization
"""

from .fabric_connector import FabricConnector
from .aws_manager import AWSServicesManager
from .multi_cloud_orchestrator import MultiCloudOrchestrator
from .security_manager import CloudSecurityManager
from .monitoring import CloudMonitor

__all__ = [
    'FabricConnector',
    'AWSServicesManager', 
    'MultiCloudOrchestrator',
    'CloudSecurityManager',
    'CloudMonitor'
]

__version__ = '1.0.0'