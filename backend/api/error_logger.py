"""
PIDS Error Logger
Captures and stores errors from backend and frontend
"""

import traceback
from datetime import datetime, timedelta
from threading import Lock

# Thread-safe error storage
_error_lock = Lock()
_errors = []
_max_errors = 100
_next_id = 1


def log_error(error_type, message, source='backend', details=None, file_path=None, line_number=None):
    """Log an error to the error store"""
    global _errors, _next_id
    
    error_entry = {
        'id': _next_id,
        'timestamp': datetime.now().isoformat(),
        'type': error_type,
        'message': str(message)[:500],
        'source': source,
        'details': details,
        'file_path': file_path,
        'line_number': line_number,
        'resolved': False
    }
    
    with _error_lock:
        _next_id += 1
        _errors.append(error_entry)
        if len(_errors) > _max_errors:
            _errors = _errors[-_max_errors:]
    
    print(f"[ERROR LOGGED] [{source.upper()}] {error_type}: {message}")
    
    return error_entry


def get_errors(source=None, error_type=None, resolved=None, limit=50):
    """Get logged errors with optional filters"""
    with _error_lock:
        filtered = _errors.copy()
    
    if source:
        filtered = [e for e in filtered if e['source'] == source]
    
    if error_type:
        filtered = [e for e in filtered if e['type'] == error_type]
    
    if resolved is not None:
        filtered = [e for e in filtered if e['resolved'] == resolved]
    
    return list(reversed(filtered[-limit:]))


def clear_errors(source=None):
    """Clear errors"""
    global _errors
    
    with _error_lock:
        if source:
            _errors = [e for e in _errors if e['source'] != source]
        else:
            _errors = []


def mark_resolved(error_id):
    """Mark an error as resolved"""
    with _error_lock:
        for error in _errors:
            if error['id'] == error_id:
                error['resolved'] = True
                error['resolved_at'] = datetime.now().isoformat()
                return True
    return False


def get_error_stats():
    """Get error statistics"""
    with _error_lock:
        errors = _errors.copy()
    
    return {
        'total': len(errors),
        'backend': len([e for e in errors if e['source'] == 'backend']),
        'frontend': len([e for e in errors if e['source'] == 'frontend']),
        'unresolved': len([e for e in errors if not e['resolved']]),
    }