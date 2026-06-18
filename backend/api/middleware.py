"""
PIDS Middleware — Error Logging + Rate Limiting
"""

import traceback
import time
from django.http import JsonResponse
from django.core.cache import cache
from api.error_logger import log_error


class ErrorLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        
        if response.status_code >= 500:
            log_error(
                error_type='ServerError',
                message=f'HTTP {response.status_code} on {request.path}',
                source='backend',
                details={'path': request.path, 'method': request.method, 'status_code': response.status_code}
            )
        
        return response

    def process_exception(self, request, exception):
        log_error(
            error_type=type(exception).__name__,
            message=str(exception),
            source='backend',
            details={'path': request.path, 'method': request.method, 'traceback': traceback.format_exc()}
        )
        return None


class RateLimitMiddleware:
    """Rate limiter — 100 requests per minute per IP.
    Auth endpoints get stricter limit (20/min) to prevent brute force.
    Read-only polling endpoints (retraining status, diagnostics) are exempt."""
    
    # Endpoints that poll frequently — exempt from rate limiting
    EXEMPT_PATHS = (
        '/api/retraining/status/',
        '/api/retraining/history/',
        '/api/retraining/backups/',
        '/api/retraining/data-stats/',
        '/api/diagnostics/',
        '/api/diverse-alerts/',
        '/api/stats/',
        '/api/traffic/',
    )

    # Prefixes that should never be rate-limited (user-initiated, infrequent,
    # and a 429 here produces a bad UX like "Failed to download PDF report").
    EXEMPT_PREFIXES = (
        '/api/reports/',
        '/api/report/',
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip rate limiting for exempt polling endpoints
        if request.method == 'GET' and (
            request.path in self.EXEMPT_PATHS
            or any(request.path.startswith(p) for p in self.EXEMPT_PREFIXES)
        ):
            return self.get_response(request)

        ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', ''))
        if ',' in ip:
            ip = ip.split(',')[0].strip()

        # Stricter limit for auth endpoints (login, setup)
        is_auth = request.path.startswith('/api/auth/')
        limit = 20 if is_auth else 300
        key = f'rate_limit:{"auth" if is_auth else "api"}:{ip}'
        
        requests_list = cache.get(key, [])
        now = time.time()
        requests_list = [t for t in requests_list if now - t < 60]
        
        if len(requests_list) >= limit:
            return JsonResponse(
                {'error': 'Rate limit exceeded. Try again later.'},
                status=429
            )
        
        requests_list.append(now)
        cache.set(key, requests_list, 120)
        
        return self.get_response(request)