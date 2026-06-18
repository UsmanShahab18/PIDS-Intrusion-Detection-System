"""
PIDS System Diagnostics API
Monitors health of all system components
"""

import os
import sys
import platform
import psutil
import time
from datetime import datetime, timedelta
from django.conf import settings
from django.db import connection
from rest_framework.decorators import api_view
from rest_framework.response import Response

from api.error_logger import log_error, get_errors, clear_errors, mark_resolved, get_error_stats

@api_view(['GET'])
def get_system_errors(request):
    """Get all logged errors"""
    source = request.GET.get('source', None)
    error_type = request.GET.get('type', None)
    resolved = request.GET.get('resolved', None)
    limit = int(request.GET.get('limit', 50))
    
    if resolved is not None:
        resolved = resolved.lower() == 'true'
    
    errors = get_errors(source=source, error_type=error_type, resolved=resolved, limit=limit)
    stats = get_error_stats()
    
    return Response({
        'errors': errors,
        'stats': stats
    })


@api_view(['POST'])
def log_frontend_error(request):
    """Log an error from frontend"""
    data = request.data
    
    error_entry = log_error(
        error_type=data.get('type', 'Unknown'),
        message=data.get('message', 'No message'),
        source='frontend',
        details=data.get('details'),
        file_path=data.get('file_path'),
        line_number=data.get('line_number')
    )
    
    return Response({'success': True, 'error': error_entry})


@api_view(['POST'])
def resolve_error(request):
    """Mark an error as resolved"""
    error_id = request.data.get('error_id')
    
    if not error_id:
        return Response({'error': 'error_id required'}, status=400)
    
    success = mark_resolved(int(error_id))
    
    return Response({'success': success})


@api_view(['POST'])
def clear_all_errors(request):
    """Clear all errors"""
    source = request.data.get('source', None)
    clear_errors(source)
    
    return Response({'success': True, 'message': f'Cleared errors for {source or "all"}'})


@api_view(['GET'])
def system_health(request):
    """Get complete system health status"""
    health = {
        'timestamp': datetime.now().isoformat(),
        'overall_status': 'healthy',
        'issues': [],
        'warnings': [],
        'components': {}
    }
    
    # Check each component
    health['components']['database'] = check_database()
    health['components']['ml_models'] = check_ml_models()
    health['components']['ollama'] = check_ollama()
    health['components']['system_resources'] = check_system_resources()
    health['components']['django'] = check_django()
    health['components']['traffic_capture'] = check_traffic_capture()
    
    # Collect all issues and warnings
    for component, status in health['components'].items():
        if status.get('status') == 'error':
            health['issues'].append({
                'component': component,
                'message': status.get('message', 'Unknown error'),
                'severity': 'critical'
            })
        elif status.get('status') == 'warning':
            health['warnings'].append({
                'component': component,
                'message': status.get('message', 'Warning'),
                'severity': 'warning'
            })
    
    # Determine overall status
    if health['issues']:
        health['overall_status'] = 'critical'
    elif health['warnings']:
        health['overall_status'] = 'warning'
    
    return Response(health)


def check_database():
    """Check database connectivity and stats"""
    try:
        start_time = time.time()
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        latency = (time.time() - start_time) * 1000  # ms
        
        # Get database stats
        from api.models import TrafficLog
        total_records = TrafficLog.objects.count()
        
        # Get recent activity
        from django.utils import timezone
        one_hour_ago = timezone.now() - timedelta(hours=1)
        recent_records = TrafficLog.objects.filter(timestamp__gte=one_hour_ago).count()
        
        status = 'healthy'
        message = 'Database connected'
        
        if latency > 100:
            status = 'warning'
            message = f'Database slow (latency: {latency:.0f}ms)'
        
        return {
            'status': status,
            'message': message,
            'details': {
                'type': 'PostgreSQL' if 'postgresql' in settings.DATABASES['default']['ENGINE'] else 'SQLite',
                'latency_ms': round(latency, 2),
                'total_records': total_records,
                'records_last_hour': recent_records,
                'database_name': settings.DATABASES['default'].get('NAME', 'N/A')
            }
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Database connection failed: {str(e)}',
            'details': {}
        }


def check_ml_models():
    """Check ML models status"""
    models_dir = os.path.join(settings.BASE_DIR, 'ml_models')
    
    required_models = {
        'stage1_xgboost.pkl': 'XGBoost Binary Classifier',
        'stage2_lightgbm.pkl': 'LightGBM Multi-class Classifier',
        'label_encoder.pkl': 'Label Encoder'
    }
    
    missing_models = []
    model_details = {}
    
    for filename, description in required_models.items():
        filepath = os.path.join(models_dir, filename)
        if os.path.exists(filepath):
            stat = os.stat(filepath)
            model_details[filename] = {
                'exists': True,
                'description': description,
                'size_mb': round(stat.st_size / (1024 * 1024), 2),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
            }
        else:
            missing_models.append(filename)
            model_details[filename] = {
                'exists': False,
                'description': description
            }
    
    # Check thresholds.json
    thresholds_path = os.path.join(models_dir, 'thresholds.json')
    if os.path.exists(thresholds_path):
        import json
        try:
            with open(thresholds_path) as f:
                thresholds = json.load(f)
            model_details['thresholds'] = thresholds
        except:
            pass
    
    if missing_models:
        return {
            'status': 'error',
            'message': f'Missing models: {", ".join(missing_models)}',
            'details': model_details
        }
    
    return {
        'status': 'healthy',
        'message': 'All ML models loaded',
        'details': model_details
    }


def check_ollama():
    """Check Ollama LLM service"""
    import requests
    
    ollama_host = getattr(settings, 'OLLAMA_HOST', 'http://localhost:11434')
    
    try:
        start_time = time.time()
        response = requests.get(f"{ollama_host}/api/tags", timeout=5)
        latency = (time.time() - start_time) * 1000
        
        if response.status_code == 200:
            data = response.json()
            models = [m['name'] for m in data.get('models', [])]
            
            # Check if required model is available
            required_model = getattr(settings, 'OLLAMA_MODEL', 'llama3')
            has_required = any(required_model in m for m in models)
            
            if not has_required:
                return {
                    'status': 'warning',
                    'message': f'Model "{required_model}" not found in Ollama',
                    'details': {
                        'host': ollama_host,
                        'available_models': models,
                        'required_model': required_model,
                        'latency_ms': round(latency, 2)
                    }
                }
            
            return {
                'status': 'healthy',
                'message': 'Ollama connected',
                'details': {
                    'host': ollama_host,
                    'available_models': models,
                    'active_model': required_model,
                    'latency_ms': round(latency, 2)
                }
            }
        else:
            return {
                'status': 'error',
                'message': f'Ollama returned status {response.status_code}',
                'details': {'host': ollama_host}
            }
    except requests.exceptions.ConnectionError:
        return {
            'status': 'error',
            'message': 'Ollama not running or not accessible',
            'details': {
                'host': ollama_host,
                'suggestion': 'Start Ollama with: ollama serve'
            }
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Ollama check failed: {str(e)}',
            'details': {'host': ollama_host}
        }


def check_system_resources():
    """Check CPU, Memory, Disk"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        status = 'healthy'
        message = 'System resources OK'
        warnings = []
        
        if cpu_percent > 90:
            status = 'warning'
            warnings.append(f'High CPU usage: {cpu_percent}%')
        
        if memory.percent > 90:
            status = 'warning'
            warnings.append(f'High memory usage: {memory.percent}%')
        
        if disk.percent > 90:
            status = 'warning'
            warnings.append(f'Low disk space: {disk.percent}% used')
        
        if warnings:
            message = '; '.join(warnings)
        
        return {
            'status': status,
            'message': message,
            'details': {
                'cpu': {
                    'percent': cpu_percent,
                    'cores': psutil.cpu_count()
                },
                'memory': {
                    'total_gb': round(memory.total / (1024**3), 2),
                    'available_gb': round(memory.available / (1024**3), 2),
                    'percent': memory.percent
                },
                'disk': {
                    'total_gb': round(disk.total / (1024**3), 2),
                    'free_gb': round(disk.free / (1024**3), 2),
                    'percent': disk.percent
                },
                'platform': {
                    'system': platform.system(),
                    'release': platform.release(),
                    'python_version': sys.version.split()[0]
                }
            }
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Failed to get system resources: {str(e)}',
            'details': {}
        }


def check_django():
    """Check Django status"""
    try:
        return {
            'status': 'healthy',
            'message': 'Django running',
            'details': {
                'debug_mode': settings.DEBUG,
                'timezone': settings.TIME_ZONE,
                'allowed_hosts': settings.ALLOWED_HOSTS,
                'installed_apps': len(settings.INSTALLED_APPS),
                'database_engine': settings.DATABASES['default']['ENGINE'].split('.')[-1]
            }
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Django check failed: {str(e)}',
            'details': {}
        }


def check_traffic_capture():
    """Check if traffic capture is active"""
    try:
        from api.models import TrafficLog
        from django.utils import timezone
        
        # Check for recent traffic (last 5 minutes)
        five_min_ago = timezone.now() - timedelta(minutes=5)
        recent_count = TrafficLog.objects.filter(timestamp__gte=five_min_ago).count()
        
        # Check last record
        last_record = TrafficLog.objects.order_by('-timestamp').first()
        last_timestamp = last_record.timestamp if last_record else None
        
        if recent_count > 0:
            return {
                'status': 'healthy',
                'message': f'Traffic capture active ({recent_count} records in last 5 min)',
                'details': {
                    'records_last_5min': recent_count,
                    'last_record': last_timestamp.isoformat() if last_timestamp else None,
                    'capture_active': True
                }
            }
        else:
            return {
                'status': 'warning',
                'message': 'No recent traffic captured',
                'details': {
                    'records_last_5min': 0,
                    'last_record': last_timestamp.isoformat() if last_timestamp else None,
                    'capture_active': False,
                    'suggestion': 'Start traffic capture or check network interface'
                }
            }
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Traffic capture check failed: {str(e)}',
            'details': {}
        }


@api_view(['GET'])
def api_endpoints_status(request):
    """Check all API endpoints"""
    from django.urls import get_resolver
    
    endpoints = []
    resolver = get_resolver()
    
    for pattern in resolver.url_patterns:
        if hasattr(pattern, 'pattern'):
            endpoints.append(str(pattern.pattern))
    
    return Response({
        'total_endpoints': len(endpoints),
        'endpoints': endpoints[:50]  # Limit to 50
    })


@api_view(['GET'])
def recent_errors(request):
    """Get recent errors from logs (if available)"""
    # This is a placeholder - in production, you'd read from log files
    return Response({
        'errors': [],
        'message': 'No recent errors'
    })