#!/usr/bin/env python3
"""
Multi-Agent Orchestrator for AI Sandbox
Manages parallel execution of multiple AI agents with resource isolation
"""

import asyncio
import uuid
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import aiohttp
import logging
from enum import Enum
import json
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AgentType(Enum):
    """Types of AI agents available"""
    DATA_ANALYST = "data_analyst"
    CODE_GENERATOR = "code_generator"
    SECURITY_AUDITOR = "security_auditor"
    DOCUMENT_PROCESSOR = "document_processor"
    API_INTEGRATOR = "api_integrator"
    TEST_RUNNER = "test_runner"

@dataclass
class AgentTask:
    """Represents a task for an AI agent"""
    task_id: str
    agent_type: AgentType
    description: str
    parameters: Dict[str, Any]
    dependencies: List[str] = field(default_factory=list)
    priority: int = 5  # 1-10, higher is more important
    timeout: int = 3600  # seconds
    status: str = "pending"
    result: Optional[Any] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

@dataclass
class AgentResource:
    """Resource allocation for an agent"""
    cpu_cores: float = 1.0
    memory_gb: float = 2.0
    disk_gb: float = 10.0
    gpu_enabled: bool = False
    network_access: List[str] = field(default_factory=list)

class MultiAgentOrchestrator:
    """Orchestrates multiple AI agents with isolation and resource management"""
    
    def __init__(self, 
                 max_concurrent_agents: int = 10,
                 session_manager_url: str = "http://session-manager:8080",
                 resource_limits: Optional[Dict[str, AgentResource]] = None):
        
        self.max_concurrent_agents = max_concurrent_agents
        self.session_manager_url = session_manager_url
        self.tasks: Dict[str, AgentTask] = {}
        self.active_sessions: Dict[str, str] = {}  # task_id -> session_id
        self.completed_tasks: List[str] = []
        self.resource_limits = resource_limits or self._default_resource_limits()
        self._task_queue = asyncio.Queue()
        self._semaphore = asyncio.Semaphore(max_concurrent_agents)
        
    def _default_resource_limits(self) -> Dict[str, AgentResource]:
        """Default resource limits per agent type"""
        return {
            AgentType.DATA_ANALYST: AgentResource(cpu_cores=2.0, memory_gb=4.0, disk_gb=20.0),
            AgentType.CODE_GENERATOR: AgentResource(cpu_cores=1.5, memory_gb=3.0, disk_gb=15.0),
            AgentType.SECURITY_AUDITOR: AgentResource(cpu_cores=1.0, memory_gb=2.0, disk_gb=10.0),
            AgentType.DOCUMENT_PROCESSOR: AgentResource(cpu_cores=1.0, memory_gb=2.0, disk_gb=10.0),
            AgentType.API_INTEGRATOR: AgentResource(cpu_cores=1.0, memory_gb=2.0, network_access=["https"]),
            AgentType.TEST_RUNNER: AgentResource(cpu_cores=2.0, memory_gb=4.0, disk_gb=20.0),
        }
        
    async def submit_task(self, task: AgentTask) -> str:
        """Submit a task to the orchestrator"""
        
        # Validate task
        if not task.task_id:
            task.task_id = str(uuid.uuid4())
            
        # Check dependencies
        for dep_id in task.dependencies:
            if dep_id not in self.tasks:
                raise ValueError(f"Dependency {dep_id} not found")
                
        # Store task
        self.tasks[task.task_id] = task
        
        # Queue for execution
        await self._task_queue.put(task.task_id)
        
        logger.info(f"Task {task.task_id} submitted: {task.description}")
        return task.task_id
        
    async def execute_workflow(self, tasks: List[AgentTask]) -> Dict[str, Any]:
        """Execute a workflow of interdependent tasks"""
        
        # Submit all tasks
        task_ids = []
        for task in tasks:
            task_id = await self.submit_task(task)
            task_ids.append(task_id)
            
        # Start execution workers
        workers = []
        for i in range(min(self.max_concurrent_agents, len(tasks))):
            worker = asyncio.create_task(self._execution_worker())
            workers.append(worker)
            
        # Wait for all tasks to complete
        results = {}
        while len(self.completed_tasks) < len(task_ids):
            await asyncio.sleep(1)
            
            # Collect results
            for task_id in task_ids:
                if task_id in self.completed_tasks and task_id not in results:
                    task = self.tasks[task_id]
                    results[task_id] = {
                        'status': task.status,
                        'result': task.result,
                        'error': task.error,
                        'duration': (task.completed_at - task.started_at).total_seconds() if task.completed_at else None
                    }
                    
        # Cancel workers
        for worker in workers:
            worker.cancel()
            
        return results
        
    async def _execution_worker(self):
        """Worker that executes tasks from the queue"""
        
        while True:
            try:
                # Get next task
                task_id = await asyncio.wait_for(self._task_queue.get(), timeout=1.0)
                
                # Check if dependencies are satisfied
                task = self.tasks[task_id]
                if not await self._check_dependencies(task):
                    # Re-queue the task
                    await self._task_queue.put(task_id)
                    await asyncio.sleep(0.5)
                    continue
                    
                # Execute with semaphore
                async with self._semaphore:
                    await self._execute_task(task)
                    
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Worker error: {e}")
                
    async def _check_dependencies(self, task: AgentTask) -> bool:
        """Check if all task dependencies are satisfied"""
        
        for dep_id in task.dependencies:
            dep_task = self.tasks.get(dep_id)
            if not dep_task or dep_task.status != "completed":
                return False
        return True
        
    async def _execute_task(self, task: AgentTask):
        """Execute a single task in an isolated agent session"""
        
        logger.info(f"Executing task {task.task_id}: {task.description}")
        task.status = "running"
        task.started_at = datetime.utcnow()
        
        try:
            # Create agent session
            session_id = await self._create_agent_session(task)
            self.active_sessions[task.task_id] = session_id
            
            # Execute task in agent
            result = await self._run_agent_task(session_id, task)
            
            # Store result
            task.result = result
            task.status = "completed"
            
        except asyncio.TimeoutError:
            task.status = "timeout"
            task.error = f"Task exceeded timeout of {task.timeout} seconds"
            logger.error(f"Task {task.task_id} timeout")
            
        except Exception as e:
            task.status = "failed"
            task.error = str(e)
            logger.error(f"Task {task.task_id} failed: {e}")
            
        finally:
            # Cleanup session
            if task.task_id in self.active_sessions:
                await self._terminate_agent_session(self.active_sessions[task.task_id])
                del self.active_sessions[task.task_id]
                
            task.completed_at = datetime.utcnow()
            self.completed_tasks.append(task.task_id)
            
    async def _create_agent_session(self, task: AgentTask) -> str:
        """Create an isolated agent session via session manager"""
        
        # Get resource limits for agent type
        resources = self.resource_limits.get(task.agent_type, AgentResource())
        
        # Prepare session configuration
        agent_config = {
            'image': f'sandbox-agent-{task.agent_type.value}:latest',
            'environment': {
                'AGENT_TYPE': task.agent_type.value,
                'TASK_ID': task.task_id,
                'TASK_TIMEOUT': str(task.timeout),
                **task.parameters
            },
            'memory_limit': f'{resources.memory_gb}g',
            'cpu_quota': int(resources.cpu_cores * 100000),
            'network_access': resources.network_access
        }
        
        # Create session via API
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.session_manager_url}/sessions",
                json={
                    'user_id': 'orchestrator',
                    'agent_config': agent_config
                }
            ) as resp:
                if resp.status != 201:
                    raise RuntimeError(f"Failed to create session: {await resp.text()}")
                    
                data = await resp.json()
                return data['session_id']
                
    async def _run_agent_task(self, session_id: str, task: AgentTask) -> Any:
        """Execute task within agent session"""
        
        # Prepare task payload
        payload = {
            'task_type': task.agent_type.value,
            'description': task.description,
            'parameters': task.parameters,
            'dependencies': {}
        }
        
        # Include dependency results
        for dep_id in task.dependencies:
            dep_task = self.tasks[dep_id]
            if dep_task.result:
                payload['dependencies'][dep_id] = dep_task.result
                
        # Execute via agent API
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.session_manager_url}/sessions/{session_id}/execute",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=task.timeout)
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"Task execution failed: {await resp.text()}")
                    
                return await resp.json()
                
    async def _terminate_agent_session(self, session_id: str):
        """Terminate an agent session"""
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.delete(
                    f"{self.session_manager_url}/sessions/{session_id}"
                ) as resp:
                    if resp.status not in (200, 204):
                        logger.warning(f"Failed to terminate session {session_id}")
        except Exception as e:
            logger.error(f"Error terminating session: {e}")
            
    async def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Get current status of a task"""
        
        task = self.tasks.get(task_id)
        if not task:
            return {'error': 'Task not found'}
            
        return {
            'task_id': task.task_id,
            'status': task.status,
            'agent_type': task.agent_type.value,
            'description': task.description,
            'created_at': task.created_at.isoformat(),
            'started_at': task.started_at.isoformat() if task.started_at else None,
            'completed_at': task.completed_at.isoformat() if task.completed_at else None,
            'result': task.result,
            'error': task.error
        }
        
    async def monitor_resources(self) -> Dict[str, Any]:
        """Monitor resource usage across all active agents"""
        
        resource_usage = {
            'active_agents': len(self.active_sessions),
            'max_agents': self.max_concurrent_agents,
            'queued_tasks': self._task_queue.qsize(),
            'completed_tasks': len(self.completed_tasks),
            'agent_types': {}
        }
        
        # Count active agents by type
        for task_id, session_id in self.active_sessions.items():
            task = self.tasks[task_id]
            agent_type = task.agent_type.value
            
            if agent_type not in resource_usage['agent_types']:
                resource_usage['agent_types'][agent_type] = {
                    'count': 0,
                    'resources': self.resource_limits[task.agent_type].__dict__
                }
                
            resource_usage['agent_types'][agent_type]['count'] += 1
            
        return resource_usage
        
    async def cleanup_completed_tasks(self, older_than_hours: int = 24):
        """Clean up completed tasks older than specified hours"""
        
        cutoff_time = datetime.utcnow() - timedelta(hours=older_than_hours)
        cleaned = 0
        
        for task_id in list(self.tasks.keys()):
            task = self.tasks[task_id]
            if (task.status in ('completed', 'failed', 'timeout') and 
                task.completed_at and task.completed_at < cutoff_time):
                
                del self.tasks[task_id]
                if task_id in self.completed_tasks:
                    self.completed_tasks.remove(task_id)
                cleaned += 1
                
        logger.info(f"Cleaned up {cleaned} old tasks")
        return cleaned

# Example usage
async def example_workflow():
    """Example multi-agent workflow"""
    
    orchestrator = MultiAgentOrchestrator(max_concurrent_agents=5)
    
    # Define workflow tasks
    tasks = [
        AgentTask(
            task_id="analyze-1",
            agent_type=AgentType.DATA_ANALYST,
            description="Analyze sales data for Q4",
            parameters={"database": "sales_db", "query": "SELECT * FROM orders WHERE quarter = 4"}
        ),
        AgentTask(
            task_id="generate-1",
            agent_type=AgentType.CODE_GENERATOR,
            description="Generate report visualization code",
            parameters={"language": "python", "library": "matplotlib"},
            dependencies=["analyze-1"]
        ),
        AgentTask(
            task_id="security-1",
            agent_type=AgentType.SECURITY_AUDITOR,
            description="Audit generated code for vulnerabilities",
            parameters={"scan_type": "static_analysis"},
            dependencies=["generate-1"]
        ),
        AgentTask(
            task_id="test-1",
            agent_type=AgentType.TEST_RUNNER,
            description="Run tests on generated code",
            parameters={"test_suite": "unit_tests"},
            dependencies=["generate-1", "security-1"]
        )
    ]
    
    # Execute workflow
    results = await orchestrator.execute_workflow(tasks)
    
    # Print results
    for task_id, result in results.items():
        print(f"Task {task_id}: {result['status']}")
        if result['error']:
            print(f"  Error: {result['error']}")
        elif result['result']:
            print(f"  Result: {json.dumps(result['result'], indent=2)}")

if __name__ == "__main__":
    asyncio.run(example_workflow())