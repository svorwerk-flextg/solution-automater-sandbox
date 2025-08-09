"""
Cloud Monitoring Module

Comprehensive monitoring and observability across cloud platforms:
- Real-time metrics collection
- Performance monitoring
- Cost tracking and optimization
- Alerting and notifications
- Dashboard and visualization
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Tuple, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import pandas as pd
import numpy as np
from collections import defaultdict, deque
import threading
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
import boto3
from azure.monitor.query import LogsQueryClient, MetricsQueryClient
from azure.identity import DefaultAzureCredential

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of metrics"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertState(Enum):
    """Alert states"""
    PENDING = "pending"
    FIRING = "firing"
    RESOLVED = "resolved"


@dataclass
class Metric:
    """Metric data point"""
    name: str
    value: float
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)
    metric_type: MetricType = MetricType.GAUGE
    unit: str = "count"


@dataclass
class Alert:
    """Alert definition"""
    alert_id: str
    name: str
    condition: str
    threshold: float
    severity: AlertSeverity
    metric_name: str
    evaluation_period: int = 5  # minutes
    datapoints_to_alarm: int = 3
    comparison_operator: str = "GreaterThanThreshold"
    actions: List[str] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True


@dataclass
class AlertInstance:
    """Active alert instance"""
    instance_id: str
    alert: Alert
    state: AlertState
    triggered_at: datetime
    resolved_at: Optional[datetime] = None
    current_value: float = 0
    message: str = ""
    notifications_sent: List[str] = field(default_factory=list)


@dataclass
class Dashboard:
    """Dashboard configuration"""
    dashboard_id: str
    name: str
    description: str
    widgets: List[Dict[str, Any]]
    refresh_interval: int = 60  # seconds
    time_range: str = "1h"  # 1h, 6h, 24h, 7d, 30d
    tags: Dict[str, str] = field(default_factory=dict)


class CloudMonitor:
    """Comprehensive cloud monitoring system"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.metrics_buffer = defaultdict(lambda: deque(maxlen=10000))
        self.alerts = {}
        self.alert_instances = {}
        self.dashboards = {}
        self._metric_aggregates = defaultdict(dict)
        self._is_running = False
        self._executor = ThreadPoolExecutor(max_workers=10)
        self._lock = threading.Lock()
        self._cloudwatch_client = None
        self._azure_metrics_client = None
        self._notification_handlers = {}
        
    def initialize(self):
        """Initialize the monitoring system"""
        try:
            # Initialize cloud monitoring clients
            self._initialize_cloud_clients()
            
            # Load default alerts
            self._load_default_alerts()
            
            # Start monitoring loops
            self._start_monitoring()
            
            logger.info("Cloud monitor initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize cloud monitor: {e}")
            raise
            
    def _initialize_cloud_clients(self):
        """Initialize cloud monitoring clients"""
        # AWS CloudWatch
        if 'aws' in self.config:
            self._cloudwatch_client = boto3.client(
                'cloudwatch',
                region_name=self.config['aws'].get('region', 'us-east-1')
            )
            
        # Azure Monitor
        if 'azure' in self.config:
            credential = DefaultAzureCredential()
            self._azure_metrics_client = MetricsQueryClient(credential)
            
    def _load_default_alerts(self):
        """Load default alert definitions"""
        default_alerts = [
            Alert(
                alert_id="high_cpu",
                name="High CPU Usage",
                condition="cpu_usage > threshold",
                threshold=80,
                severity=AlertSeverity.HIGH,
                metric_name="system.cpu.usage",
                evaluation_period=5,
                datapoints_to_alarm=3,
                actions=["email", "slack"]
            ),
            Alert(
                alert_id="high_memory",
                name="High Memory Usage",
                condition="memory_usage > threshold",
                threshold=90,
                severity=AlertSeverity.HIGH,
                metric_name="system.memory.usage",
                evaluation_period=5,
                datapoints_to_alarm=3,
                actions=["email", "slack"]
            ),
            Alert(
                alert_id="disk_space",
                name="Low Disk Space",
                condition="disk_free < threshold",
                threshold=10,
                severity=AlertSeverity.CRITICAL,
                metric_name="system.disk.free_percent",
                evaluation_period=10,
                datapoints_to_alarm=2,
                comparison_operator="LessThanThreshold",
                actions=["email", "pagerduty"]
            ),
            Alert(
                alert_id="error_rate",
                name="High Error Rate",
                condition="error_rate > threshold",
                threshold=5,
                severity=AlertSeverity.HIGH,
                metric_name="application.error_rate",
                evaluation_period=5,
                datapoints_to_alarm=2,
                actions=["email", "slack"]
            ),
            Alert(
                alert_id="response_time",
                name="Slow Response Time",
                condition="response_time > threshold",
                threshold=1000,
                severity=AlertSeverity.MEDIUM,
                metric_name="application.response_time",
                evaluation_period=5,
                datapoints_to_alarm=3,
                actions=["email"]
            ),
            Alert(
                alert_id="cost_anomaly",
                name="Cost Anomaly Detected",
                condition="daily_cost > threshold",
                threshold=500,
                severity=AlertSeverity.MEDIUM,
                metric_name="cloud.daily_cost",
                evaluation_period=1440,  # 24 hours
                datapoints_to_alarm=1,
                actions=["email"]
            )
        ]
        
        for alert in default_alerts:
            self.add_alert(alert)
            
    def _start_monitoring(self):
        """Start background monitoring tasks"""
        self._is_running = True
        
        # Start metric aggregation thread
        threading.Thread(target=self._metric_aggregation_loop, daemon=True).start()
        
        # Start alert evaluation thread
        threading.Thread(target=self._alert_evaluation_loop, daemon=True).start()
        
        # Start metric cleanup thread
        threading.Thread(target=self._metric_cleanup_loop, daemon=True).start()
        
    def _metric_aggregation_loop(self):
        """Background loop for metric aggregation"""
        while self._is_running:
            try:
                self._aggregate_metrics()
                time.sleep(60)  # Aggregate every minute
            except Exception as e:
                logger.error(f"Metric aggregation error: {e}")
                
    def _alert_evaluation_loop(self):
        """Background loop for alert evaluation"""
        while self._is_running:
            try:
                self._evaluate_alerts()
                time.sleep(30)  # Evaluate every 30 seconds
            except Exception as e:
                logger.error(f"Alert evaluation error: {e}")
                
    def _metric_cleanup_loop(self):
        """Background loop for metric cleanup"""
        while self._is_running:
            try:
                self._cleanup_old_metrics()
                time.sleep(3600)  # Cleanup every hour
            except Exception as e:
                logger.error(f"Metric cleanup error: {e}")
                
    # Metric Management
    def record_metric(self, name: str, value: float, 
                     tags: Optional[Dict[str, str]] = None,
                     metric_type: MetricType = MetricType.GAUGE,
                     unit: str = "count"):
        """Record a metric data point"""
        metric = Metric(
            name=name,
            value=value,
            timestamp=datetime.now(),
            tags=tags or {},
            metric_type=metric_type,
            unit=unit
        )
        
        # Create metric key including tags
        metric_key = self._create_metric_key(name, tags)
        
        with self._lock:
            self.metrics_buffer[metric_key].append(metric)
            
        # Send to cloud monitoring if configured
        self._send_to_cloud_monitoring(metric)
        
    def _create_metric_key(self, name: str, tags: Optional[Dict[str, str]]) -> str:
        """Create unique key for metric including tags"""
        if not tags:
            return name
            
        # Sort tags for consistent keys
        tag_str = ",".join(f"{k}={v}" for k, v in sorted(tags.items()))
        return f"{name}:{tag_str}"
        
    def _send_to_cloud_monitoring(self, metric: Metric):
        """Send metric to cloud monitoring services"""
        # Send to CloudWatch
        if self._cloudwatch_client:
            try:
                dimensions = [
                    {'Name': k, 'Value': v} for k, v in metric.tags.items()
                ]
                
                self._cloudwatch_client.put_metric_data(
                    Namespace='SolutionAutomater',
                    MetricData=[{
                        'MetricName': metric.name,
                        'Value': metric.value,
                        'Unit': metric.unit,
                        'Timestamp': metric.timestamp,
                        'Dimensions': dimensions
                    }]
                )
            except Exception as e:
                logger.error(f"Failed to send metric to CloudWatch: {e}")
                
    def get_metrics(self, name: str, tags: Optional[Dict[str, str]] = None,
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None) -> List[Metric]:
        """Retrieve metrics for a given name and tags"""
        metric_key = self._create_metric_key(name, tags)
        
        with self._lock:
            metrics = list(self.metrics_buffer.get(metric_key, []))
            
        # Apply time filters
        if start_time:
            metrics = [m for m in metrics if m.timestamp >= start_time]
        if end_time:
            metrics = [m for m in metrics if m.timestamp <= end_time]
            
        return metrics
        
    def _aggregate_metrics(self):
        """Aggregate metrics for different time windows"""
        with self._lock:
            for metric_key, metrics in self.metrics_buffer.items():
                if not metrics:
                    continue
                    
                # Get recent metrics
                now = datetime.now()
                recent_metrics = [m for m in metrics 
                                if m.timestamp > now - timedelta(minutes=5)]
                
                if recent_metrics:
                    values = [m.value for m in recent_metrics]
                    
                    # Calculate aggregates
                    self._metric_aggregates[metric_key] = {
                        'count': len(values),
                        'sum': sum(values),
                        'avg': np.mean(values),
                        'min': min(values),
                        'max': max(values),
                        'p50': np.percentile(values, 50),
                        'p95': np.percentile(values, 95),
                        'p99': np.percentile(values, 99),
                        'stddev': np.std(values),
                        'last_updated': now
                    }
                    
    def get_metric_statistics(self, name: str, tags: Optional[Dict[str, str]] = None,
                            period: int = 300) -> Dict[str, float]:
        """Get aggregated statistics for a metric"""
        metric_key = self._create_metric_key(name, tags)
        
        with self._lock:
            return self._metric_aggregates.get(metric_key, {})
            
    # Alert Management
    def add_alert(self, alert: Alert):
        """Add an alert definition"""
        with self._lock:
            self.alerts[alert.alert_id] = alert
            
        logger.info(f"Added alert: {alert.name}")
        
    def update_alert(self, alert_id: str, updates: Dict[str, Any]):
        """Update an existing alert"""
        with self._lock:
            if alert_id not in self.alerts:
                raise ValueError(f"Alert {alert_id} not found")
                
            alert = self.alerts[alert_id]
            for key, value in updates.items():
                if hasattr(alert, key):
                    setattr(alert, key, value)
                    
    def delete_alert(self, alert_id: str):
        """Delete an alert"""
        with self._lock:
            if alert_id in self.alerts:
                del self.alerts[alert_id]
                
            # Also remove any active instances
            instances_to_remove = [
                instance_id for instance_id, instance in self.alert_instances.items()
                if instance.alert.alert_id == alert_id
            ]
            
            for instance_id in instances_to_remove:
                del self.alert_instances[instance_id]
                
    def _evaluate_alerts(self):
        """Evaluate all active alerts"""
        with self._lock:
            alerts = list(self.alerts.values())
            
        for alert in alerts:
            if not alert.enabled:
                continue
                
            try:
                self._evaluate_single_alert(alert)
            except Exception as e:
                logger.error(f"Failed to evaluate alert {alert.alert_id}: {e}")
                
    def _evaluate_single_alert(self, alert: Alert):
        """Evaluate a single alert"""
        # Get recent metrics for the alert
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=alert.evaluation_period)
        
        metrics = self.get_metrics(alert.metric_name, alert.tags, start_time, end_time)
        
        if not metrics:
            return
            
        # Check if threshold is breached
        values = [m.value for m in metrics]
        
        if alert.comparison_operator == "GreaterThanThreshold":
            breached_count = sum(1 for v in values if v > alert.threshold)
        elif alert.comparison_operator == "LessThanThreshold":
            breached_count = sum(1 for v in values if v < alert.threshold)
        elif alert.comparison_operator == "GreaterThanOrEqualToThreshold":
            breached_count = sum(1 for v in values if v >= alert.threshold)
        elif alert.comparison_operator == "LessThanOrEqualToThreshold":
            breached_count = sum(1 for v in values if v <= alert.threshold)
        else:
            breached_count = 0
            
        current_value = values[-1] if values else 0
        
        # Check if we need to trigger alert
        if breached_count >= alert.datapoints_to_alarm:
            self._trigger_alert(alert, current_value)
        else:
            self._resolve_alert(alert)
            
    def _trigger_alert(self, alert: Alert, current_value: float):
        """Trigger an alert"""
        # Check if alert is already firing
        active_instance = None
        for instance in self.alert_instances.values():
            if instance.alert.alert_id == alert.alert_id and instance.state == AlertState.FIRING:
                active_instance = instance
                break
                
        if active_instance:
            # Update current value
            active_instance.current_value = current_value
        else:
            # Create new alert instance
            instance_id = f"{alert.alert_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            instance = AlertInstance(
                instance_id=instance_id,
                alert=alert,
                state=AlertState.FIRING,
                triggered_at=datetime.now(),
                current_value=current_value,
                message=f"{alert.name}: {current_value} {alert.comparison_operator} {alert.threshold}"
            )
            
            with self._lock:
                self.alert_instances[instance_id] = instance
                
            # Send notifications
            self._send_alert_notifications(instance)
            
            logger.warning(f"Alert triggered: {alert.name} (value: {current_value})")
            
    def _resolve_alert(self, alert: Alert):
        """Resolve an alert if it's currently firing"""
        resolved_instances = []
        
        with self._lock:
            for instance_id, instance in self.alert_instances.items():
                if (instance.alert.alert_id == alert.alert_id and 
                    instance.state == AlertState.FIRING):
                    instance.state = AlertState.RESOLVED
                    instance.resolved_at = datetime.now()
                    resolved_instances.append(instance)
                    
        for instance in resolved_instances:
            self._send_resolution_notifications(instance)
            logger.info(f"Alert resolved: {alert.name}")
            
    def _send_alert_notifications(self, instance: AlertInstance):
        """Send alert notifications"""
        for action in instance.alert.actions:
            handler = self._notification_handlers.get(action)
            if handler:
                try:
                    handler(instance)
                    instance.notifications_sent.append(action)
                except Exception as e:
                    logger.error(f"Failed to send {action} notification: {e}")
                    
    def _send_resolution_notifications(self, instance: AlertInstance):
        """Send alert resolution notifications"""
        # Send to same channels as alert
        for action in instance.alert.actions:
            handler = self._notification_handlers.get(f"{action}_resolution")
            if handler:
                try:
                    handler(instance)
                except Exception as e:
                    logger.error(f"Failed to send {action} resolution notification: {e}")
                    
    def register_notification_handler(self, action: str, handler: Callable):
        """Register a notification handler for an action type"""
        self._notification_handlers[action] = handler
        
    # Dashboard Management
    def create_dashboard(self, name: str, description: str,
                        widgets: List[Dict[str, Any]]) -> str:
        """Create a monitoring dashboard"""
        dashboard_id = f"dashboard_{len(self.dashboards) + 1}"
        
        dashboard = Dashboard(
            dashboard_id=dashboard_id,
            name=name,
            description=description,
            widgets=widgets
        )
        
        with self._lock:
            self.dashboards[dashboard_id] = dashboard
            
        logger.info(f"Created dashboard: {name}")
        return dashboard_id
        
    def get_dashboard_data(self, dashboard_id: str) -> Dict[str, Any]:
        """Get data for dashboard widgets"""
        dashboard = self.dashboards.get(dashboard_id)
        if not dashboard:
            raise ValueError(f"Dashboard {dashboard_id} not found")
            
        # Parse time range
        time_range_map = {
            '1h': timedelta(hours=1),
            '6h': timedelta(hours=6),
            '24h': timedelta(hours=24),
            '7d': timedelta(days=7),
            '30d': timedelta(days=30)
        }
        
        time_delta = time_range_map.get(dashboard.time_range, timedelta(hours=1))
        end_time = datetime.now()
        start_time = end_time - time_delta
        
        dashboard_data = {
            'dashboard_id': dashboard_id,
            'name': dashboard.name,
            'description': dashboard.description,
            'time_range': dashboard.time_range,
            'widgets': []
        }
        
        # Process each widget
        for widget in dashboard.widgets:
            widget_data = self._get_widget_data(widget, start_time, end_time)
            dashboard_data['widgets'].append(widget_data)
            
        return dashboard_data
        
    def _get_widget_data(self, widget: Dict[str, Any],
                        start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Get data for a single widget"""
        widget_type = widget.get('type', 'line_chart')
        metrics = widget.get('metrics', [])
        
        widget_data = {
            'type': widget_type,
            'title': widget.get('title', 'Untitled'),
            'data': []
        }
        
        for metric_config in metrics:
            metric_name = metric_config.get('name')
            metric_tags = metric_config.get('tags', {})
            
            if widget_type in ['line_chart', 'area_chart']:
                # Get time series data
                metrics = self.get_metrics(metric_name, metric_tags, start_time, end_time)
                
                series_data = {
                    'name': metric_config.get('label', metric_name),
                    'data': [
                        {
                            'timestamp': m.timestamp.isoformat(),
                            'value': m.value
                        }
                        for m in metrics
                    ]
                }
                
                widget_data['data'].append(series_data)
                
            elif widget_type == 'gauge':
                # Get latest value
                stats = self.get_metric_statistics(metric_name, metric_tags)
                
                widget_data['data'] = {
                    'value': stats.get('avg', 0),
                    'min': widget.get('min', 0),
                    'max': widget.get('max', 100)
                }
                
            elif widget_type == 'stat':
                # Get aggregated stats
                stats = self.get_metric_statistics(metric_name, metric_tags)
                
                widget_data['data'] = {
                    'value': stats.get(widget.get('stat', 'avg'), 0),
                    'unit': widget.get('unit', '')
                }
                
        return widget_data
        
    # Cost Monitoring
    def track_cost(self, provider: str, service: str, cost: float,
                  currency: str = "USD", tags: Optional[Dict[str, str]] = None):
        """Track cloud service costs"""
        cost_tags = tags or {}
        cost_tags.update({
            'provider': provider,
            'service': service,
            'currency': currency
        })
        
        self.record_metric(
            name='cloud.cost',
            value=cost,
            tags=cost_tags,
            metric_type=MetricType.GAUGE,
            unit=currency
        )
        
        # Also track daily cost
        self.record_metric(
            name='cloud.daily_cost',
            value=cost,
            tags=cost_tags,
            metric_type=MetricType.GAUGE,
            unit=currency
        )
        
    def get_cost_report(self, start_date: datetime, end_date: datetime,
                       group_by: List[str] = None) -> pd.DataFrame:
        """Generate cost report for specified period"""
        # Get all cost metrics
        cost_metrics = []
        
        with self._lock:
            for metric_key, metrics in self.metrics_buffer.items():
                if 'cloud.cost' in metric_key:
                    for metric in metrics:
                        if start_date <= metric.timestamp <= end_date:
                            cost_metrics.append({
                                'timestamp': metric.timestamp,
                                'cost': metric.value,
                                **metric.tags
                            })
                            
        if not cost_metrics:
            return pd.DataFrame()
            
        # Convert to DataFrame
        df = pd.DataFrame(cost_metrics)
        
        # Group by specified columns
        if group_by:
            grouped = df.groupby(group_by + [pd.Grouper(key='timestamp', freq='D')])
            return grouped['cost'].sum().reset_index()
        else:
            return df
            
    # Performance Monitoring
    def start_timer(self, name: str, tags: Optional[Dict[str, str]] = None) -> str:
        """Start a performance timer"""
        timer_id = f"{name}_{datetime.now().timestamp()}"
        
        # Store start time
        timer_key = f"timer_{timer_id}"
        with self._lock:
            self.metrics_buffer[timer_key].append(
                Metric(name=name, value=time.time(), timestamp=datetime.now(), tags=tags or {})
            )
            
        return timer_id
        
    def stop_timer(self, timer_id: str):
        """Stop a performance timer and record duration"""
        timer_key = f"timer_{timer_id}"
        
        with self._lock:
            timer_metrics = list(self.metrics_buffer.get(timer_key, []))
            
        if timer_metrics:
            start_metric = timer_metrics[0]
            duration_ms = (time.time() - start_metric.value) * 1000
            
            # Record duration metric
            self.record_metric(
                name=f"{start_metric.name}.duration",
                value=duration_ms,
                tags=start_metric.tags,
                metric_type=MetricType.HISTOGRAM,
                unit="milliseconds"
            )
            
            # Clean up timer
            with self._lock:
                if timer_key in self.metrics_buffer:
                    del self.metrics_buffer[timer_key]
                    
    # Health Checks
    def record_health_check(self, service: str, healthy: bool,
                          response_time: Optional[float] = None,
                          details: Optional[Dict[str, Any]] = None):
        """Record health check result"""
        tags = {
            'service': service,
            'healthy': str(healthy)
        }
        
        # Record health status
        self.record_metric(
            name='health.status',
            value=1 if healthy else 0,
            tags=tags,
            metric_type=MetricType.GAUGE
        )
        
        # Record response time if provided
        if response_time is not None:
            self.record_metric(
                name='health.response_time',
                value=response_time,
                tags={'service': service},
                metric_type=MetricType.GAUGE,
                unit='milliseconds'
            )
            
    def get_service_health(self) -> Dict[str, Any]:
        """Get current health status of all services"""
        health_status = {
            'timestamp': datetime.now().isoformat(),
            'services': {}
        }
        
        # Get recent health metrics
        end_time = datetime.now()
        start_time = end_time - timedelta(minutes=5)
        
        with self._lock:
            for metric_key, metrics in self.metrics_buffer.items():
                if 'health.status' in metric_key:
                    recent_metrics = [m for m in metrics 
                                    if m.timestamp >= start_time]
                    
                    if recent_metrics:
                        latest = recent_metrics[-1]
                        service = latest.tags.get('service', 'unknown')
                        
                        health_status['services'][service] = {
                            'healthy': latest.value == 1,
                            'last_check': latest.timestamp.isoformat()
                        }
                        
        return health_status
        
    # Cleanup
    def _cleanup_old_metrics(self):
        """Clean up old metrics to prevent memory growth"""
        retention_period = timedelta(hours=24)  # Keep 24 hours of metrics
        cutoff_time = datetime.now() - retention_period
        
        with self._lock:
            for metric_key in list(self.metrics_buffer.keys()):
                # Filter out old metrics
                self.metrics_buffer[metric_key] = deque(
                    (m for m in self.metrics_buffer[metric_key] 
                     if m.timestamp > cutoff_time),
                    maxlen=10000
                )
                
                # Remove empty buffers
                if not self.metrics_buffer[metric_key]:
                    del self.metrics_buffer[metric_key]
                    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring system status"""
        with self._lock:
            total_metrics = sum(len(metrics) for metrics in self.metrics_buffer.values())
            
        return {
            'running': self._is_running,
            'metrics': {
                'total_series': len(self.metrics_buffer),
                'total_points': total_metrics
            },
            'alerts': {
                'total': len(self.alerts),
                'enabled': sum(1 for a in self.alerts.values() if a.enabled),
                'firing': sum(1 for i in self.alert_instances.values() 
                            if i.state == AlertState.FIRING)
            },
            'dashboards': len(self.dashboards),
            'notification_handlers': list(self._notification_handlers.keys())
        }
        
    def shutdown(self):
        """Shutdown the monitoring system"""
        logger.info("Shutting down cloud monitor")
        
        self._is_running = False
        self._executor.shutdown(wait=True)
        
        # Clear buffers
        with self._lock:
            self.metrics_buffer.clear()
            
        logger.info("Cloud monitor shutdown complete")