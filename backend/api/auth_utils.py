"""
PIDS - JWT Authentication Utilities
Pure Python JWT implementation using Django's crypto.
No third-party JWT library needed — uses HMAC-SHA256 directly.
"""
import json
import time
import hmac
import hashlib
import base64
from functools import wraps
from django.conf import settings
from rest_framework.response import Response
from rest_framework import status


# =============================================================================
# TOKEN CONFIG
# =============================================================================
ACCESS_TOKEN_EXPIRY = 60 * 60          # 1 hour
REFRESH_TOKEN_EXPIRY = 60 * 60 * 24 * 7  # 7 days
JWT_SECRET = getattr(settings, 'JWT_SECRET', None) or getattr(settings, 'SECRET_KEY', 'change-me-in-production')


# =============================================================================
# JWT CORE (HMAC-SHA256)
# =============================================================================

def _b64_encode(data: bytes) -> str:
    """URL-safe base64 encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def _b64_decode(s: str) -> bytes:
    """URL-safe base64 decode with padding restoration."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.urlsafe_b64decode(s)


def _create_jwt(payload: dict) -> str:
    """Create a JWT token (header.payload.signature)."""
    header = {'alg': 'HS256', 'typ': 'JWT'}
    header_b64 = _b64_encode(json.dumps(header).encode())
    payload_b64 = _b64_encode(json.dumps(payload).encode())

    message = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        JWT_SECRET.encode(), message.encode(), hashlib.sha256
    ).digest()
    signature_b64 = _b64_encode(signature)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def _verify_jwt(token: str) -> dict:
    """Verify JWT signature and return payload. Raises ValueError on failure."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError('Invalid token format')

        header_b64, payload_b64, signature_b64 = parts

        # Verify signature
        message = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(
            JWT_SECRET.encode(), message.encode(), hashlib.sha256
        ).digest()
        actual_sig = _b64_decode(signature_b64)

        if not hmac.compare_digest(expected_sig, actual_sig):
            raise ValueError('Invalid signature')

        # Decode payload
        payload = json.loads(_b64_decode(payload_b64))

        # Check expiry
        if payload.get('exp', 0) < time.time():
            raise ValueError('Token expired')

        return payload

    except (json.JSONDecodeError, KeyError) as e:
        raise ValueError(f'Malformed token: {e}')


# =============================================================================
# PUBLIC API
# =============================================================================

def generate_tokens(user) -> dict:
    """Generate access + refresh token pair for a user."""
    now = time.time()

    access_payload = {
        'user_id': user.id,
        'username': user.username,
        'role': user.role.name if user.role else None,
        'type': 'access',
        'iat': now,
        'exp': now + ACCESS_TOKEN_EXPIRY,
    }

    refresh_payload = {
        'user_id': user.id,
        'type': 'refresh',
        'iat': now,
        'exp': now + REFRESH_TOKEN_EXPIRY,
    }

    return {
        'access': _create_jwt(access_payload),
        'refresh': _create_jwt(refresh_payload),
        'expires_in': ACCESS_TOKEN_EXPIRY,
    }


def refresh_access_token(refresh_token: str) -> dict:
    """Generate new access token from a valid refresh token."""
    try:
        payload = _verify_jwt(refresh_token)
        if payload.get('type') != 'refresh':
            return {'error': 'Not a refresh token'}

        from api.models import CustomUser
        user = CustomUser.objects.select_related('role').get(id=payload['user_id'])

        if not user.is_active:
            return {'error': 'Account disabled'}

        now = time.time()
        access_payload = {
            'user_id': user.id,
            'username': user.username,
            'role': user.role.name if user.role else None,
            'type': 'access',
            'iat': now,
            'exp': now + ACCESS_TOKEN_EXPIRY,
        }
        return {
            'access': _create_jwt(access_payload),
            'expires_in': ACCESS_TOKEN_EXPIRY,
        }
    except ValueError as e:
        return {'error': str(e)}
    except Exception:
        return {'error': 'Invalid refresh token'}


def get_user_from_token(request):
    """Extract and validate user from Authorization header.
    Returns (user, None) on success or (None, error_response) on failure."""
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')

    if not auth_header.startswith('Bearer '):
        return None, Response(
            {'error': 'Authorization header must be: Bearer <token>'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    token = auth_header[7:]  # Strip 'Bearer '

    try:
        payload = _verify_jwt(token)
    except ValueError as e:
        return None, Response(
            {'error': str(e)},
            status=status.HTTP_401_UNAUTHORIZED
        )

    if payload.get('type') != 'access':
        return None, Response(
            {'error': 'Not an access token'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    from api.models import CustomUser
    try:
        user = CustomUser.objects.select_related('role').get(
            id=payload['user_id'], is_active=True
        )
    except CustomUser.DoesNotExist:
        return None, Response(
            {'error': 'User not found or disabled'},
            status=status.HTTP_401_UNAUTHORIZED
        )

    return user, None


# =============================================================================
# DECORATORS
# =============================================================================

def jwt_required(view_func):
    """Decorator: requires valid JWT access token."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user, error = get_user_from_token(request)
        if error:
            return error
        request.user = user
        return view_func(request, *args, **kwargs)
    return wrapper


def admin_required(view_func):
    """Decorator: requires JWT + admin role."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        user, error = get_user_from_token(request)
        if error:
            return error
        if not user.is_admin and not user.is_superuser:
            return Response(
                {'error': 'Admin access required'},
                status=status.HTTP_403_FORBIDDEN
            )
        request.user = user
        return view_func(request, *args, **kwargs)
    return wrapper


def role_required(*allowed_roles):
    """Decorator: requires JWT + one of the specified roles.
    Usage: @role_required('admin', 'security_analyst', 'ml_engineer')
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            user, error = get_user_from_token(request)
            if error:
                return error
            if user.is_superuser:
                request.user = user
                return view_func(request, *args, **kwargs)
            if not user.role or user.role.name not in allowed_roles:
                return Response(
                    {'error': f'Access denied. Required role: {", ".join(allowed_roles)}'},
                    status=status.HTTP_403_FORBIDDEN
                )
            request.user = user
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def page_access_required(page_name):
    """Decorator: requires JWT + page permission.
    Usage: @page_access_required('retraining')
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            user, error = get_user_from_token(request)
            if error:
                return error
            if not user.has_page_access(page_name):
                return Response(
                    {'error': f'No access to {page_name}'},
                    status=status.HTTP_403_FORBIDDEN
                )
            request.user = user
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator