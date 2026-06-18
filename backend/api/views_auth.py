"""
PIDS - Authentication & RBAC Views (JWT)
Endpoints: login, register, refresh, me, permissions, user management, setup
"""
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth import authenticate
from django.db.models import Count
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from api.models import CustomUser, Role, AuditLog
from api.auth_utils import (
    generate_tokens, refresh_access_token, get_user_from_token,
    jwt_required, admin_required, role_required
)


# =============================================================================
# PUBLIC ENDPOINTS (no auth required)
# =============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    """
    Authenticate user and return JWT tokens.
    SQL-injection safe: uses Django ORM parameterised queries.
    Includes account lockout after 5 failed attempts.
    """
    username = request.data.get('username', '').strip()
    password = request.data.get('password', '')

    if not username or not password:
        return Response({'error': 'Username and password required'},
                        status=status.HTTP_400_BAD_REQUEST)

    # Check if user exists (parameterised query - SQL injection safe)
    try:
        user = CustomUser.objects.get(username=username)
    except CustomUser.DoesNotExist:
        return Response({'error': 'Invalid credentials'},
                        status=status.HTTP_401_UNAUTHORIZED)

    # Check account lockout
    if user.is_locked():
        remaining = (user.locked_until - timezone.now()).seconds // 60
        return Response({
            'error': f'Account locked. Try again in {remaining} minutes.',
            'locked': True
        }, status=status.HTTP_403_FORBIDDEN)

    # Authenticate
    auth_user = authenticate(username=username, password=password)

    if auth_user is None:
        # Failed login
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.locked_until = timezone.now() + timedelta(minutes=15)
            user.save(update_fields=['failed_login_attempts', 'locked_until'])
            _log_audit(user, 'ACCOUNT_LOCKED', 'User',
                       details={'reason': '5 failed login attempts'},
                       ip=_get_ip(request))
            return Response({
                'error': 'Account locked for 15 minutes due to failed attempts.',
                'locked': True
            }, status=status.HTTP_403_FORBIDDEN)
        user.save(update_fields=['failed_login_attempts'])
        return Response({'error': 'Invalid credentials'},
                        status=status.HTTP_401_UNAUTHORIZED)

    if not auth_user.is_active:
        return Response({'error': 'Account is disabled'},
                        status=status.HTTP_403_FORBIDDEN)

    # Success - reset failed attempts
    auth_user.failed_login_attempts = 0
    auth_user.locked_until = None
    auth_user.last_login = timezone.now()
    auth_user.save(update_fields=['failed_login_attempts', 'locked_until', 'last_login'])

    # Generate JWT tokens
    tokens = generate_tokens(auth_user)

    _log_audit(auth_user, 'LOGIN', 'User',
               details={'username': auth_user.username, 'role': auth_user.role.name if auth_user.role else 'none'},
               ip=_get_ip(request))

    return Response({
        'access': tokens['access'],
        'refresh': tokens['refresh'],
        'user': _serialize_user(auth_user)
    })


@api_view(['POST'])
@permission_classes([AllowAny])
def token_refresh(request):
    """Refresh access token using refresh token."""
    refresh_token = request.data.get('refresh', '')
    if not refresh_token:
        return Response({'error': 'Refresh token required'},
                        status=status.HTTP_400_BAD_REQUEST)

    result = refresh_access_token(refresh_token)
    if 'error' in result:
        return Response(result, status=status.HTTP_401_UNAUTHORIZED)
    return Response(result)


@api_view(['GET'])
@permission_classes([AllowAny])
def check_setup(request):
    """Check if system needs initial setup (no admin exists yet)."""
    admin_exists = CustomUser.objects.filter(
        role__name=Role.ADMIN, is_active=True
    ).exists()
    return Response({
        'setup_required': not admin_exists,
        'user_count': CustomUser.objects.count()
    })


def _validate_password(password):
    """Enforce strong password: uppercase, lowercase, number, symbol, 8+ chars."""
    import re
    errors = []
    if len(password) < 8:
        errors.append('at least 8 characters')
    if not re.search(r'[A-Z]', password):
        errors.append('an uppercase letter')
    if not re.search(r'[a-z]', password):
        errors.append('a lowercase letter')
    if not re.search(r'[0-9]', password):
        errors.append('a number')
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]', password):
        errors.append('a special character (!@#$...)')
    return errors


@api_view(['POST'])
@permission_classes([AllowAny])
def initial_setup(request):
    """
    First-time setup wizard - creates the initial admin account.
    Only works when NO admin exists in the system.
    """
    # Security: only allow if no admin exists
    if CustomUser.objects.filter(role__name=Role.ADMIN, is_active=True).exists():
        return Response({'error': 'Admin already exists. Setup not allowed.'},
                        status=status.HTTP_403_FORBIDDEN)

    username = request.data.get('username', '').strip()
    password = request.data.get('password', '')
    email = request.data.get('email', '').strip()
    full_name = request.data.get('full_name', '').strip()

    if not username or not password:
        return Response({'error': 'Username and password required'},
                        status=status.HTTP_400_BAD_REQUEST)
    pw_errors = _validate_password(password)
    if pw_errors:
        return Response({'error': f'Password must contain: {", ".join(pw_errors)}'},
                        status=status.HTTP_400_BAD_REQUEST)

    # Ensure roles exist
    _ensure_roles()

    admin_role = Role.objects.get(name=Role.ADMIN)
    user = CustomUser.objects.create_user(
        username=username, password=password, email=email,
        full_name=full_name, role=admin_role,
        is_staff=True, is_superuser=True
    )

    _log_audit(user, 'INITIAL_SETUP', 'User',
               details={'created_admin': username}, ip=_get_ip(request))

    tokens = generate_tokens(user)
    return Response({
        'message': 'Admin account created successfully',
        'access': tokens['access'],
        'refresh': tokens['refresh'],
        'user': _serialize_user(user)
    }, status=status.HTTP_201_CREATED)


# =============================================================================
# AUTHENTICATED ENDPOINTS
# =============================================================================

@api_view(['GET'])
@jwt_required
def get_me(request):
    """Get current user profile and permissions."""
    return Response(_serialize_user(request.user))


@api_view(['GET'])
@jwt_required
def get_permissions(request):
    """Get current user's page permissions for navbar rendering."""
    return Response({
        'pages': request.user.page_permissions,
        'role': request.user.role.name if request.user.role else None,
        'role_display': request.user.role.get_name_display() if request.user.role else 'No Role',
        'is_admin': request.user.is_admin,
    })


@api_view(['PUT'])
@jwt_required
def update_profile(request):
    """Update own profile (including avatar)."""
    user = request.user
    user.full_name = request.data.get('full_name', user.full_name)
    user.email = request.data.get('email', user.email)
    user.phone = request.data.get('phone', user.phone)
    user.department = request.data.get('department', user.department)

    # Avatar update
    if 'avatar_type' in request.data:
        avatar_type = request.data.get('avatar_type', 'initials')
        avatar_data = request.data.get('avatar_data', '')
        if avatar_type in ('preset', 'custom', 'initials'):
            user.avatar_type = avatar_type
            user.avatar_data = avatar_data if avatar_type != 'initials' else ''

    user.save()

    _log_audit(user, 'PROFILE_UPDATE', 'User',
               details={
                   'updated_fields': [k for k in ['full_name', 'email', 'phone', 'department', 'avatar_type'] if k in request.data],
                   'username': user.username,
               },
               ip=_get_ip(request))
    return Response(_serialize_user(user))


@api_view(['POST'])
@jwt_required
def change_password(request):
    """Change own password."""
    old_password = request.data.get('old_password', '')
    new_password = request.data.get('new_password', '')

    if not request.user.check_password(old_password):
        return Response({'error': 'Current password is incorrect'},
                        status=status.HTTP_400_BAD_REQUEST)
    if old_password == new_password:
        return Response({'error': 'New password must be different from current password'},
                        status=status.HTTP_400_BAD_REQUEST)
    pw_errors = _validate_password(new_password)
    if pw_errors:
        return Response({'error': f'Password must contain: {", ".join(pw_errors)}'},
                        status=status.HTTP_400_BAD_REQUEST)

    request.user.set_password(new_password)
    request.user.must_change_password = False
    request.user.save()

    _log_audit(request.user, 'PASSWORD_CHANGE', 'User',
               details={'username': request.user.username, 'forced': request.user.must_change_password},
               ip=_get_ip(request))
    return Response({'message': 'Password changed successfully'})


@api_view(['POST'])
@jwt_required
def logout(request):
    """Logout - audit log only (JWT is stateless)."""
    _log_audit(request.user, 'LOGOUT', 'User',
               details={'username': request.user.username},
               ip=_get_ip(request))
    return Response({'message': 'Logged out'})


# =============================================================================
# ADMIN ENDPOINTS (admin role required)
# =============================================================================

@api_view(['GET'])
@admin_required
def list_users(request):
    """List all users (admin only)."""
    users = CustomUser.objects.select_related('role').all()
    return Response([_serialize_user(u) for u in users])


@api_view(['POST'])
@admin_required
def create_user(request):
    """Create a new user (admin only)."""
    username = request.data.get('username', '').strip()
    password = request.data.get('password', '')
    role_name = request.data.get('role', '')
    email = request.data.get('email', '').strip()
    full_name = request.data.get('full_name', '').strip()

    if not username or not password or not role_name:
        return Response({'error': 'username, password, and role are required'},
                        status=status.HTTP_400_BAD_REQUEST)

    # Admin accounts can only be created via command line
    if role_name == Role.ADMIN:
        return Response({'error': 'Admin accounts can only be created via command line (python manage.py createsuperuser or initial setup)'},
                        status=status.HTTP_400_BAD_REQUEST)

    pw_errors = _validate_password(password)
    if pw_errors:
        return Response({'error': f'Password must contain: {", ".join(pw_errors)}'},
                        status=status.HTTP_400_BAD_REQUEST)

    if CustomUser.objects.filter(username=username).exists():
        return Response({'error': 'Username already exists'},
                        status=status.HTTP_400_BAD_REQUEST)

    try:
        role = Role.objects.get(name=role_name)
    except Role.DoesNotExist:
        roles = list(Role.objects.values_list('name', flat=True))
        return Response({'error': f'Invalid role. Options: {roles}'},
                        status=status.HTTP_400_BAD_REQUEST)

    user = CustomUser.objects.create_user(
        username=username, password=password, email=email,
        full_name=full_name, role=role,
        must_change_password=True  # Force password change on first login
    )

    _log_audit(request.user, 'CREATE_USER', 'User',
               entity_id=str(user.id),
               details={'created': username, 'role': role_name},
               ip=_get_ip(request))

    return Response(_serialize_user(user), status=status.HTTP_201_CREATED)


@api_view(['PUT'])
@admin_required
def update_user(request, user_id):
    """Update a user's role or status (admin only)."""
    try:
        user = CustomUser.objects.get(id=user_id)
    except CustomUser.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    # Prevent admin from changing their own role
    if user.id == request.user.id and 'role' in request.data:
        return Response({'error': 'Cannot change your own role'},
                        status=status.HTTP_400_BAD_REQUEST)

    # Prevent changing another admin's role
    if user.role and user.role.name == Role.ADMIN and 'role' in request.data:
        return Response({'error': 'Cannot change an Administrator role. Admin accounts can only be managed via command line.'},
                        status=status.HTTP_400_BAD_REQUEST)

    # Prevent promoting anyone to admin via UI
    if request.data.get('role') == Role.ADMIN:
        return Response({'error': 'Admin role can only be assigned via command line'},
                        status=status.HTTP_400_BAD_REQUEST)

    if 'role' in request.data:
        try:
            role = Role.objects.get(name=request.data['role'])
            user.role = role
        except Role.DoesNotExist:
            return Response({'error': 'Invalid role'}, status=status.HTTP_400_BAD_REQUEST)

    if 'is_active' in request.data:
        user.is_active = request.data['is_active']

    if 'full_name' in request.data:
        user.full_name = request.data['full_name']

    # Unlock account if locked
    if request.data.get('unlock', False):
        user.failed_login_attempts = 0
        user.locked_until = None

    user.save()

    _log_audit(request.user, 'UPDATE_USER', 'User',
               entity_id=str(user.id),
               details={
                   'updated': user.username,
                   'changes': {k: str(request.data[k]) for k in ['role', 'is_active', 'full_name', 'unlock'] if k in request.data},
               },
               ip=_get_ip(request))

    return Response(_serialize_user(user))


@api_view(['DELETE'])
@admin_required
def delete_user(request, user_id):
    """Delete a user (admin only). Cannot delete yourself or the last admin."""
    try:
        user = CustomUser.objects.get(id=user_id)
    except CustomUser.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    if user.id == request.user.id:
        return Response({'error': 'Cannot delete yourself'},
                        status=status.HTTP_400_BAD_REQUEST)

    # Prevent deleting the last admin
    if user.role and user.role.name == Role.ADMIN:
        admin_count = CustomUser.objects.filter(role__name=Role.ADMIN, is_active=True).count()
        if admin_count <= 1:
            return Response({'error': 'Cannot delete the last administrator'},
                            status=status.HTTP_400_BAD_REQUEST)

    username = user.username
    user.delete()

    _log_audit(request.user, 'DELETE_USER', 'User',
               details={'deleted': username}, ip=_get_ip(request))

    return Response({'message': f'User {username} deleted'})


@api_view(['GET'])
@admin_required
def list_roles(request):
    """List all roles with their permissions."""
    roles = Role.objects.all()
    return Response([{
        'name': r.name,
        'display': r.get_name_display(),
        'description': r.description,
        'permissions': r.page_permissions,
        'user_count': r.users.count()
    } for r in roles])


@api_view(['GET'])
@admin_required
def get_audit_logs(request):
    """Get audit logs (admin only)."""
    limit = min(int(request.GET.get('limit', 50)), 500)
    logs = AuditLog.objects.select_related('user')[:limit]
    return Response([{
        'timestamp': l.timestamp.isoformat(),
        'user': l.user.username if l.user else 'System',
        'action': l.action,
        'entity': l.affected_entity,
        'entity_id': l.entity_id,
        'details': l.details,
        'ip': l.ip_address,
    } for l in logs])


# =============================================================================
# HELPERS
# =============================================================================

def _serialize_user(user):
    """Serialize user for API response."""
    return {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'full_name': user.full_name,
        'phone': user.phone,
        'department': user.department,
        'role': user.role.name if user.role else None,
        'role_display': user.role.get_name_display() if user.role else 'No Role',
        'is_active': user.is_active,
        'is_admin': user.is_admin,
        'must_change_password': user.must_change_password,
        'pages': user.page_permissions,
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'date_joined': user.date_joined.isoformat(),
        'avatar_type': user.avatar_type,
        'avatar_data': user.avatar_data,
    }


def _log_audit(user, action, entity, entity_id=None, details=None, ip=None):
    """Create audit log entry."""
    try:
        AuditLog.objects.create(
            user=user, action=action, affected_entity=entity,
            entity_id=entity_id, details=details or {}, ip_address=ip
        )
    except Exception:
        pass  # Don't break the main operation if audit fails


def _get_ip(request):
    """Get client IP from request."""
    xff = request.META.get('HTTP_X_FORWARDED_FOR')
    return xff.split(',')[0].strip() if xff else request.META.get('REMOTE_ADDR')


def _ensure_roles():
    """Create default roles if they don't exist."""
    defaults = Role.get_default_permissions()
    descriptions = {
        Role.ADMIN: 'Full system access including user management',
        Role.SECURITY_ANALYST: 'View attacks, alerts, reports, and traffic',
        Role.NETWORK_MONITOR: 'View dashboard and traffic logs',
        Role.IT_SUPPORT: 'View dashboard and system diagnostics',
        Role.ML_ENGINEER: 'Manage ML models, retraining, and LLM configuration',
    }
    for role_name, permissions in defaults.items():
        Role.objects.update_or_create(
            name=role_name,
            defaults={
                'page_permissions': permissions,
                'description': descriptions.get(role_name, '')
            }
        )