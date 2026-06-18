"""
PIDS - Database Models (v3 - RBAC + JWT)
Clean schema: only tables the system actually uses.
Designed for easy transfer between machines.

TABLES:
  1. Role              - 5 predefined roles
  2. User (CustomUser) - extends Django AbstractUser with role FK
  3. TrafficLog        - captured packets + ML predictions + 31 features
  4. Alert             - security alerts from detections
  5. ThreatAnalysis    - LLM analysis results linked to alerts
  6. Report            - generated PDF/CSV/JSON reports
  7. ModelVersion      - ML model version tracking
  8. AuditLog          - user action audit trail

REMOVED FROM ERD (not used by the system):
  - NetworkPacket     (redundant - TrafficLog already stores packet data)
  - FeatureVector     (redundant - features stored as JSON in TrafficLog)
  - ExternalIntegration (no external APIs integrated yet)
  - ConfigurationParameter (settings.py handles this)
  - AuthenticationSession  (JWT is stateless - no session table needed)
  - LLMAgent          (single Ollama instance, config in settings.py)
  - TrainingDataset   (TrafficLog.used_for_training flag handles this)
"""
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone


# =============================================================================
# 1. ROLE
# =============================================================================
class Role(models.Model):
    """
    Predefined roles for RBAC.
    Created automatically via data migration.
    """
    ADMIN           = 'admin'
    SECURITY_ANALYST = 'security_analyst'
    NETWORK_MONITOR  = 'network_monitor'
    IT_SUPPORT       = 'it_support'
    ML_ENGINEER      = 'ml_engineer'

    ROLE_CHOICES = [
        (ADMIN,            'Administrator'),
        (SECURITY_ANALYST, 'Security Analyst'),
        (NETWORK_MONITOR,  'Network Monitor'),
        (IT_SUPPORT,       'IT Support Staff'),
        (ML_ENGINEER,      'ML/AI Engineer'),
    ]

    name = models.CharField(max_length=30, unique=True, choices=ROLE_CHOICES)
    description = models.CharField(max_length=200, blank=True)

    # Page-level permissions stored as JSON for flexibility
    page_permissions = models.JSONField(default=dict)

    class Meta:
        db_table = 'pids_role'

    def __str__(self):
        return self.get_name_display()

    @classmethod
    def get_default_permissions(cls):
        """Default page permissions for each role."""
        return {
            cls.ADMIN: {
                'dashboard': True, 'traffic': True, 'threats': True,
                'reports': True, 'retraining': True, 'diagnostics': True,
                'architecture': True, 'admin_panel': True,
            },
            cls.SECURITY_ANALYST: {
                'dashboard': True, 'traffic': True, 'threats': True,
                'reports': True, 'retraining': False, 'diagnostics': False,
                'architecture': True, 'admin_panel': False,
            },
            cls.NETWORK_MONITOR: {
                'dashboard': True, 'traffic': True, 'threats': False,
                'reports': False, 'retraining': False, 'diagnostics': False,
                'architecture': True, 'admin_panel': False,
            },
            cls.IT_SUPPORT: {
                'dashboard': True, 'traffic': False, 'threats': False,
                'reports': False, 'retraining': False, 'diagnostics': True,
                'architecture': True, 'admin_panel': False,
            },
            cls.ML_ENGINEER: {
                'dashboard': True, 'traffic': True, 'threats': True,
                'reports': True, 'retraining': True, 'diagnostics': True,
                'architecture': True, 'admin_panel': False,
            },
        }


# =============================================================================
# 2. USER (Custom - extends Django AbstractUser)
# =============================================================================
class CustomUser(AbstractUser):
    """
    Custom user with role-based access control.
    Uses Django's built-in password hashing (PBKDF2 + SHA256).
    """
    role = models.ForeignKey(
        Role, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='users'
    )

    # Profile fields
    full_name = models.CharField(max_length=150, blank=True)
    phone = models.CharField(max_length=20, blank=True)
    department = models.CharField(max_length=100, blank=True)

    # Avatar (stored in DB, not localStorage)
    AVATAR_TYPE_CHOICES = [
        ('preset', 'Preset Avatar'),
        ('custom', 'Custom Upload'),
        ('initials', 'Initials'),
    ]
    avatar_type = models.CharField(max_length=10, choices=AVATAR_TYPE_CHOICES, default='initials')
    avatar_data = models.TextField(blank=True, default='')  # preset ID or base64 image

    # Security
    must_change_password = models.BooleanField(default=False)
    failed_login_attempts = models.IntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'pids_user'

    def __str__(self):
        role_name = self.role.get_name_display() if self.role else 'No Role'
        return f"{self.username} ({role_name})"

    @property
    def is_admin(self):
        return self.role and self.role.name == Role.ADMIN

    @property
    def page_permissions(self):
        """Get this user's page permissions from their role."""
        if self.is_superuser:
            return {k: True for k in Role.get_default_permissions()[Role.ADMIN]}
        if self.role:
            return self.role.page_permissions
        return {}

    def has_page_access(self, page_name):
        """Check if user can access a specific page."""
        if self.is_superuser:
            return True
        return self.page_permissions.get(page_name, False)

    def is_locked(self):
        """Check if account is locked due to failed attempts."""
        if self.locked_until and self.locked_until > timezone.now():
            return True
        if self.locked_until and self.locked_until <= timezone.now():
            self.locked_until = None
            self.failed_login_attempts = 0
            self.save(update_fields=['locked_until', 'failed_login_attempts'])
        return False


# =============================================================================
# 3. TRAFFIC LOG
# =============================================================================
class TrafficLog(models.Model):
    """Captured network traffic with ML predictions and 31 features."""
    STATUS_CHOICES = [
        ('Normal', 'Normal'),
        ('Suspicious', 'Suspicious'),
        ('Attack', 'Attack'),
    ]

    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    src_ip = models.CharField(max_length=45, db_index=True)
    dst_ip = models.CharField(max_length=45, db_index=True)
    src_port = models.IntegerField(default=0)
    dst_port = models.IntegerField(default=0)
    protocol = models.CharField(max_length=10)
    length = models.IntegerField(default=0)

    # ML Predictions
    prediction = models.CharField(max_length=100)
    confidence = models.FloatField(default=0.0)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, db_index=True)
    attack_type = models.CharField(max_length=100, null=True, blank=True)

    # 31 features (JSON)
    features = models.JSONField(null=True, blank=True)

    # LLM Analysis
    llm_analyzed = models.BooleanField(default=False)
    llm_result = models.TextField(null=True, blank=True)

    # Flags
    involves_local_pc = models.BooleanField(default=False)
    is_zero_day = models.BooleanField(default=False)
    used_for_training = models.BooleanField(default=False)

    # Acknowledgement
    acknowledged = models.BooleanField(default=False)
    acknowledged_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'pids_traffic_log'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['status', 'timestamp']),
            models.Index(fields=['src_ip', 'timestamp']),
            models.Index(fields=['status', 'prediction']),
            models.Index(fields=['llm_analyzed']),
            models.Index(fields=['is_zero_day']),
            models.Index(fields=['used_for_training']),
            models.Index(fields=['prediction', 'timestamp']),
            models.Index(fields=['-timestamp']),
        ]

    def __str__(self):
        return f"{self.timestamp} {self.src_ip}→{self.dst_ip} ({self.status})"


# =============================================================================
# 4. ALERT
# =============================================================================
class Alert(models.Model):
    """Security alerts generated from detected attacks."""
    SEVERITY_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical'),
    ]

    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    traffic_log = models.ForeignKey(
        TrafficLog, on_delete=models.CASCADE,
        null=True, blank=True, related_name='alerts'
    )

    alert_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    message = models.TextField()

    source_ip = models.CharField(max_length=45, null=True, blank=True)
    destination_ip = models.CharField(max_length=45, null=True, blank=True)

    # ML scores
    xgboost_score = models.FloatField(null=True, blank=True)
    lightgbm_score = models.FloatField(null=True, blank=True)
    confidence = models.FloatField(default=0.0)

    # Status
    status = models.CharField(max_length=20, default='New')
    resolved = models.BooleanField(default=False)
    acknowledged_by = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='acknowledged_alerts'
    )
    acknowledged_time = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'pids_alert'
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.alert_type} ({self.severity})"


# Legacy alias
SystemAlert = Alert


# =============================================================================
# 5. THREAT ANALYSIS
# =============================================================================
class ThreatAnalysis(models.Model):
    """LLM-powered threat analysis results."""
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='analyses')

    threat_characterization = models.TextField()
    attack_vectors = models.JSONField(default=list)
    recommendations = models.JSONField(default=list)

    confidence = models.FloatField(default=0.0)
    analysis_time = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'pids_threat_analysis'
        ordering = ['-analysis_time']

    def __str__(self):
        return f"Analysis for Alert #{self.alert_id}"


# =============================================================================
# 6. REPORT
# =============================================================================
class Report(models.Model):
    """Generated security reports."""
    REPORT_TYPE_CHOICES = [
        ('Daily', 'Daily'), ('Weekly', 'Weekly'),
        ('Monthly', 'Monthly'), ('Custom', 'Custom'),
        ('Incident', 'Incident'),
    ]
    FORMAT_CHOICES = [
        ('PDF', 'PDF'), ('CSV', 'CSV'), ('JSON', 'JSON'),
    ]

    report_type = models.CharField(max_length=20, choices=REPORT_TYPE_CHOICES)
    title = models.CharField(max_length=200)
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    generated_time = models.DateTimeField(auto_now_add=True)
    generated_by = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='reports'
    )
    format = models.CharField(max_length=10, choices=FORMAT_CHOICES, default='PDF')
    file_path = models.CharField(max_length=500, null=True, blank=True)

    # Stats snapshot
    total_traffic = models.IntegerField(default=0)
    total_attacks = models.IntegerField(default=0)
    total_suspicious = models.IntegerField(default=0)
    ai_summary = models.TextField(null=True, blank=True)

    class Meta:
        db_table = 'pids_report'
        ordering = ['-generated_time']

    def __str__(self):
        return f"{self.report_type} Report - {self.generated_time}"


# =============================================================================
# 7. MODEL VERSION
# =============================================================================
class ModelVersion(models.Model):
    """Tracks ML model versions and performance."""
    version_id = models.CharField(max_length=50, unique=True)
    model_type = models.CharField(max_length=50)

    created_time = models.DateTimeField(auto_now_add=True)
    accuracy = models.FloatField(null=True, blank=True)
    false_positive_rate = models.FloatField(null=True, blank=True)

    is_active = models.BooleanField(default=False)
    training_data_count = models.IntegerField(default=0)
    file_path = models.CharField(max_length=500)

    trained_by = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='trained_models'
    )

    class Meta:
        db_table = 'pids_model_version'
        ordering = ['-created_time']

    def __str__(self):
        return f"{self.model_type} v{self.version_id}"


# =============================================================================
# 8. AUDIT LOG
# =============================================================================
class AuditLog(models.Model):
    """Audit trail for user actions. Written by middleware, not users."""
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='audit_logs'
    )

    action = models.CharField(max_length=100)
    affected_entity = models.CharField(max_length=100)
    entity_id = models.CharField(max_length=100, null=True, blank=True)
    details = models.JSONField(default=dict)
    ip_address = models.CharField(max_length=45, null=True, blank=True)

    class Meta:
        db_table = 'pids_audit_log'
        ordering = ['-timestamp']

    def __str__(self):
        username = self.user.username if self.user else 'System'
        return f"{self.timestamp} {username} - {self.action}"


# =============================================================================
# 9. ENGINE CONFIG (singleton — selects active detection engine)
# =============================================================================
class EngineConfig(models.Model):
    """
    Singleton row that records which detection engine is currently active.

    Only one row is ever expected (enforced by :meth:`get_active` always
    using ``pk=1``). The sniffer process reads this value via a 5-second
    cache (see ``api.detection.engines.engine_registry``) so admin
    changes propagate to long-running capture loops without a restart.
    """

    ENGINE_CHOICES = [
        ('ml', 'ML (XGBoost + LightGBM)'),
        ('dl', 'DL (Two-Stage DNN)'),
        ('gnn', 'GNN (Two-Stage Graph Neural Network)'),
    ]

    active_engine = models.CharField(max_length=10, choices=ENGINE_CHOICES, default='dl')
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='engine_config_updates',
    )

    class Meta:
        db_table = 'pids_engine_config'
        verbose_name = 'Engine Configuration'
        verbose_name_plural = 'Engine Configuration'

    def __str__(self) -> str:
        return f"EngineConfig(active={self.active_engine}, updated_at={self.updated_at})"

    def save(self, *args, **kwargs):
        """Force singleton: always pk=1."""
        self.pk = 1
        super().save(*args, **kwargs)

    @classmethod
    def get_active(cls) -> 'EngineConfig':
        """
        Return the singleton row, creating it with the configured default
        engine on first access. Safe to call from any code path.
        """
        from django.conf import settings
        default = getattr(settings, 'DETECTION_ENGINE_DEFAULT', 'dl')
        obj, _created = cls.objects.get_or_create(
            pk=1, defaults={'active_engine': default}
        )
        return obj