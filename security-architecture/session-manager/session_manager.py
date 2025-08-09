#!/usr/bin/env python3
"""
Session Lifecycle Manager for AI Sandbox
Handles automated creation, monitoring, and destruction of agent containers
"""

import asyncio
import docker
import boto3
import json
import logging
import os
import secrets
import shutil
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from cryptography.fernet import Fernet
from dataclasses import dataclass, asdict
import aioboto3
from contextlib import asynccontextmanager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class Session:
    """Represents an AI agent session"""
    session_id: str
    agent_id: str
    container_id: Optional[str]
    created_at: datetime
    expires_at: datetime
    status: str  # 'pending', 'active', 'terminating', 'terminated'
    user_id: str
    workspace_path: str
    artifacts_path: str
    metadata: Dict[str, Any]

class SessionManager:
    """Manages lifecycle of AI agent sessions with security enforcement"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.docker_client = docker.from_env()
        self.sessions: Dict[str, Session] = {}
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        
        # S3 configuration
        self.s3_bucket = config.get('s3_bucket', 'ai-sandbox-artifacts')
        self.s3_region = config.get('aws_region', 'us-east-1')
        
        # Session defaults
        self.default_timeout = config.get('session_timeout', 3600)
        self.max_sessions_per_user = config.get('max_sessions_per_user', 5)
        self.workspace_base = Path('/var/lib/sessions/workspaces')
        self.artifacts_base = Path('/var/lib/sessions/artifacts')
        
        # Ensure directories exist
        self.workspace_base.mkdir(parents=True, exist_ok=True)
        self.artifacts_base.mkdir(parents=True, exist_ok=True)
        
    async def create_session(self, user_id: str, agent_config: Dict[str, Any]) -> Session:
        """Create a new AI agent session"""
        
        # Check user session limit
        user_sessions = [s for s in self.sessions.values() if s.user_id == user_id and s.status == 'active']
        if len(user_sessions) >= self.max_sessions_per_user:
            raise ValueError(f"User {user_id} has reached maximum session limit")
        
        # Generate session ID
        session_id = f"session-{secrets.token_urlsafe(16)}"
        agent_id = f"agent-{secrets.token_urlsafe(8)}"
        
        # Create workspace directories
        workspace_path = self.workspace_base / session_id
        artifacts_path = self.artifacts_base / session_id
        workspace_path.mkdir(parents=True, exist_ok=True)
        artifacts_path.mkdir(parents=True, exist_ok=True)
        
        # Set permissions (read-only for agent)
        os.chmod(workspace_path, 0o755)
        os.chmod(artifacts_path, 0o755)
        
        # Create session object
        session = Session(
            session_id=session_id,
            agent_id=agent_id,
            container_id=None,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(seconds=self.default_timeout),
            status='pending',
            user_id=user_id,
            workspace_path=str(workspace_path),
            artifacts_path=str(artifacts_path),
            metadata=agent_config
        )
        
        # Start container
        try:
            container = await self._create_container(session, agent_config)
            session.container_id = container.id
            session.status = 'active'
            
            # Store session
            self.sessions[session_id] = session
            
            # Log session creation
            await self._audit_log('session_created', session)
            
            logger.info(f"Created session {session_id} for user {user_id}")
            return session
            
        except Exception as e:
            # Cleanup on failure
            shutil.rmtree(workspace_path, ignore_errors=True)
            shutil.rmtree(artifacts_path, ignore_errors=True)
            logger.error(f"Failed to create session: {e}")
            raise
            
    async def _create_container(self, session: Session, agent_config: Dict[str, Any]) -> docker.models.containers.Container:
        """Create and configure agent container with security restrictions"""
        
        # Container configuration
        container_config = {
            'image': agent_config.get('image', 'sandbox-agent:latest'),
            'name': f"sandbox-{session.agent_id}",
            'hostname': session.agent_id,
            'environment': {
                'SESSION_ID': session.session_id,
                'AGENT_ID': session.agent_id,
                'USER_ID': session.user_id,
                'WORKSPACE': '/workspace',
                'ARTIFACTS': '/artifacts',
                'TIMEOUT': str(self.default_timeout),
                **agent_config.get('environment', {})
            },
            'volumes': {
                session.workspace_path: {'bind': '/workspace', 'mode': 'rw'},
                session.artifacts_path: {'bind': '/artifacts', 'mode': 'rw'},
                '/tmp': {'bind': '/tmp', 'mode': 'rw', 'tmpfs': {'size': '1G'}}
            },
            'network': 'agent-network',
            'mem_limit': agent_config.get('memory_limit', '4g'),
            'memswap_limit': agent_config.get('memory_limit', '4g'),
            'cpu_quota': agent_config.get('cpu_quota', 200000),  # 2 CPUs
            'cpu_period': 100000,
            'read_only': True,  # Read-only root filesystem
            'security_opt': ['no-new-privileges:true'],
            'cap_drop': ['ALL'],  # Drop all capabilities
            'auto_remove': False,  # We'll handle cleanup
            'detach': True
        }
        
        # Add resource limits
        if 'ulimits' not in container_config:
            container_config['ulimits'] = [
                docker.types.Ulimit(name='nofile', soft=1024, hard=2048),
                docker.types.Ulimit(name='nproc', soft=512, hard=1024)
            ]
        
        # Create container
        container = self.docker_client.containers.run(**container_config)
        
        # Apply additional restrictions via runtime
        await self._apply_security_policies(container)
        
        return container
        
    async def _apply_security_policies(self, container):
        """Apply additional runtime security policies"""
        # This would include:
        # - AppArmor/SELinux profiles
        # - Seccomp filters
        # - Network policies
        # Implementation depends on specific requirements
        pass
        
    async def terminate_session(self, session_id: str, reason: str = "user_requested") -> None:
        """Terminate a session and cleanup resources"""
        
        session = self.sessions.get(session_id)
        if not session:
            logger.warning(f"Session {session_id} not found")
            return
            
        if session.status == 'terminated':
            logger.info(f"Session {session_id} already terminated")
            return
            
        logger.info(f"Terminating session {session_id}, reason: {reason}")
        session.status = 'terminating'
        
        try:
            # Save artifacts to S3
            await self._save_artifacts(session)
            
            # Stop and remove container
            if session.container_id:
                try:
                    container = self.docker_client.containers.get(session.container_id)
                    container.stop(timeout=10)
                    container.remove(force=True)
                except docker.errors.NotFound:
                    pass
                except Exception as e:
                    logger.error(f"Error stopping container: {e}")
                    
            # Secure deletion of workspace
            await self._secure_delete(session.workspace_path)
            await self._secure_delete(session.artifacts_path)
            
            # Update session status
            session.status = 'terminated'
            
            # Audit log
            await self._audit_log('session_terminated', session, {'reason': reason})
            
        except Exception as e:
            logger.error(f"Error during session termination: {e}")
            # Force cleanup even on error
            if Path(session.workspace_path).exists():
                shutil.rmtree(session.workspace_path, ignore_errors=True)
            if Path(session.artifacts_path).exists():
                shutil.rmtree(session.artifacts_path, ignore_errors=True)
            raise
            
    async def _save_artifacts(self, session: Session) -> None:
        """Save session artifacts to S3 before deletion"""
        
        artifacts_path = Path(session.artifacts_path)
        if not artifacts_path.exists() or not any(artifacts_path.iterdir()):
            logger.info(f"No artifacts to save for session {session.session_id}")
            return
            
        async with aioboto3.Session().client(
            's3',
            region_name=self.s3_region
        ) as s3_client:
            
            # Create timestamp-based prefix
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            s3_prefix = f"sessions/{session.user_id}/{session.session_id}/{timestamp}"
            
            # Upload each artifact
            for artifact_file in artifacts_path.rglob('*'):
                if artifact_file.is_file():
                    relative_path = artifact_file.relative_to(artifacts_path)
                    s3_key = f"{s3_prefix}/{relative_path}"
                    
                    # Encrypt before upload
                    with open(artifact_file, 'rb') as f:
                        encrypted_data = self.cipher.encrypt(f.read())
                        
                    await s3_client.put_object(
                        Bucket=self.s3_bucket,
                        Key=s3_key,
                        Body=encrypted_data,
                        ServerSideEncryption='AES256',
                        Metadata={
                            'session_id': session.session_id,
                            'user_id': session.user_id,
                            'original_name': str(relative_path)
                        }
                    )
                    
            logger.info(f"Saved artifacts for session {session.session_id} to S3")
            
    async def _secure_delete(self, path: str) -> None:
        """Securely delete files by overwriting before removal"""
        
        path_obj = Path(path)
        if not path_obj.exists():
            return
            
        if path_obj.is_file():
            # Overwrite file with random data
            size = path_obj.stat().st_size
            with open(path, 'wb') as f:
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
            path_obj.unlink()
        else:
            # Recursively secure delete directory
            for item in path_obj.rglob('*'):
                if item.is_file():
                    await self._secure_delete(str(item))
            shutil.rmtree(path, ignore_errors=True)
            
    async def monitor_sessions(self) -> None:
        """Monitor active sessions and enforce timeouts"""
        
        while True:
            try:
                current_time = datetime.utcnow()
                expired_sessions = []
                
                for session_id, session in self.sessions.items():
                    if session.status != 'active':
                        continue
                        
                    # Check expiration
                    if current_time > session.expires_at:
                        expired_sessions.append(session_id)
                        continue
                        
                    # Check container health
                    if session.container_id:
                        try:
                            container = self.docker_client.containers.get(session.container_id)
                            if container.status != 'running':
                                expired_sessions.append(session_id)
                        except docker.errors.NotFound:
                            expired_sessions.append(session_id)
                            
                # Terminate expired sessions
                for session_id in expired_sessions:
                    await self.terminate_session(session_id, reason='timeout')
                    
                # Wait before next check
                await asyncio.sleep(30)
                
            except Exception as e:
                logger.error(f"Error in session monitor: {e}")
                await asyncio.sleep(60)
                
    async def extend_session(self, session_id: str, duration: int) -> Session:
        """Extend session timeout"""
        
        session = self.sessions.get(session_id)
        if not session or session.status != 'active':
            raise ValueError(f"Session {session_id} not found or not active")
            
        # Limit extension
        max_extension = self.config.get('max_extension', 7200)
        duration = min(duration, max_extension)
        
        # Update expiration
        session.expires_at = datetime.utcnow() + timedelta(seconds=duration)
        
        # Audit log
        await self._audit_log('session_extended', session, {'duration': duration})
        
        logger.info(f"Extended session {session_id} by {duration} seconds")
        return session
        
    async def get_session_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get current session status"""
        
        session = self.sessions.get(session_id)
        if not session:
            return None
            
        status = {
            'session_id': session.session_id,
            'agent_id': session.agent_id,
            'status': session.status,
            'created_at': session.created_at.isoformat(),
            'expires_at': session.expires_at.isoformat(),
            'time_remaining': max(0, (session.expires_at - datetime.utcnow()).total_seconds())
        }
        
        # Add container stats if active
        if session.container_id and session.status == 'active':
            try:
                container = self.docker_client.containers.get(session.container_id)
                stats = container.stats(stream=False)
                status['container_stats'] = {
                    'cpu_usage': self._calculate_cpu_usage(stats),
                    'memory_usage': self._calculate_memory_usage(stats),
                    'network_io': stats.get('networks', {})
                }
            except:
                pass
                
        return status
        
    def _calculate_cpu_usage(self, stats: Dict) -> float:
        """Calculate CPU usage percentage from container stats"""
        try:
            cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                       stats['precpu_stats']['cpu_usage']['total_usage']
            system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                          stats['precpu_stats']['system_cpu_usage']
            
            if system_delta > 0:
                cpu_percent = (cpu_delta / system_delta) * 100.0
                return round(cpu_percent, 2)
        except:
            pass
        return 0.0
        
    def _calculate_memory_usage(self, stats: Dict) -> Dict[str, int]:
        """Calculate memory usage from container stats"""
        try:
            memory_stats = stats.get('memory_stats', {})
            return {
                'usage': memory_stats.get('usage', 0),
                'limit': memory_stats.get('limit', 0),
                'percent': round((memory_stats.get('usage', 0) / memory_stats.get('limit', 1)) * 100, 2)
            }
        except:
            return {'usage': 0, 'limit': 0, 'percent': 0}
            
    async def _audit_log(self, event_type: str, session: Session, extra_data: Dict[str, Any] = None) -> None:
        """Write audit log entry"""
        
        audit_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'session_id': session.session_id,
            'user_id': session.user_id,
            'agent_id': session.agent_id,
            'status': session.status
        }
        
        if extra_data:
            audit_entry['extra'] = extra_data
            
        # Write to audit log
        audit_path = Path('/var/log/audit/session_manager.jsonl')
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(audit_path, 'a') as f:
            f.write(json.dumps(audit_entry) + '\n')
            
        # Also send to centralized logging if configured
        if self.config.get('centralized_logging'):
            # Implementation for CloudWatch, Splunk, etc.
            pass
            
    async def cleanup_orphaned_resources(self) -> None:
        """Clean up any orphaned containers or directories"""
        
        logger.info("Starting orphaned resource cleanup")
        
        # Find orphaned containers
        all_containers = self.docker_client.containers.list(all=True, filters={'label': 'sandbox=true'})
        active_container_ids = {s.container_id for s in self.sessions.values() if s.container_id}
        
        for container in all_containers:
            if container.id not in active_container_ids:
                logger.info(f"Removing orphaned container {container.id}")
                try:
                    container.stop(timeout=10)
                    container.remove(force=True)
                except:
                    pass
                    
        # Find orphaned workspaces
        active_workspaces = {s.workspace_path for s in self.sessions.values()}
        for workspace in self.workspace_base.iterdir():
            if str(workspace) not in active_workspaces:
                logger.info(f"Removing orphaned workspace {workspace}")
                shutil.rmtree(workspace, ignore_errors=True)
                
        logger.info("Orphaned resource cleanup completed")

async def main():
    """Main entry point for session manager"""
    
    # Load configuration
    config = {
        'session_timeout': int(os.getenv('SESSION_TIMEOUT', '3600')),
        'max_sessions_per_user': int(os.getenv('MAX_SESSIONS_PER_USER', '5')),
        's3_bucket': os.getenv('S3_BUCKET', 'ai-sandbox-artifacts'),
        'aws_region': os.getenv('AWS_DEFAULT_REGION', 'us-east-1'),
        'max_extension': int(os.getenv('MAX_EXTENSION', '7200')),
        'centralized_logging': os.getenv('CENTRALIZED_LOGGING', 'false').lower() == 'true'
    }
    
    # Create session manager
    manager = SessionManager(config)
    
    # Start monitoring task
    monitor_task = asyncio.create_task(manager.monitor_sessions())
    
    # Periodic cleanup
    async def periodic_cleanup():
        while True:
            await asyncio.sleep(3600)  # Every hour
            await manager.cleanup_orphaned_resources()
            
    cleanup_task = asyncio.create_task(periodic_cleanup())
    
    try:
        # Run forever
        await asyncio.gather(monitor_task, cleanup_task)
    except KeyboardInterrupt:
        logger.info("Shutting down session manager")
        
if __name__ == "__main__":
    asyncio.run(main())