"""
PIDS - API URLs (v3 - with JWT Auth + RBAC)
"""
from django.urls import path
from . import views
from api import views_auth
from api.views_retraining import (
    training_status, training_history, data_stats,
    model_backups, start_training, cancel_training, restore_backup, reset_flags
)
from api.views_diagnostics import (
    system_health, api_endpoints_status, recent_errors,
    get_system_errors, log_frontend_error, resolve_error, clear_all_errors
)
from api.views_engine import engine_status, engine_select, engine_info
from api.views_zeroday import scan_zero_day, recent_zero_day

urlpatterns = [
    # =================================================================
    # AUTH ENDPOINTS (public)
    # =================================================================
    path('auth/login/', views_auth.login, name='login'),
    path('auth/refresh/', views_auth.token_refresh, name='token-refresh'),
    path('auth/setup/check/', views_auth.check_setup, name='check-setup'),
    path('auth/setup/', views_auth.initial_setup, name='initial-setup'),

    # AUTH ENDPOINTS (authenticated)
    path('auth/me/', views_auth.get_me, name='get-me'),
    path('auth/permissions/', views_auth.get_permissions, name='get-permissions'),
    path('auth/profile/', views_auth.update_profile, name='update-profile'),
    path('auth/change-password/', views_auth.change_password, name='change-password'),
    path('auth/logout/', views_auth.logout, name='logout'),

    # =================================================================
    # ADMIN ENDPOINTS (admin role required)
    # =================================================================
    path('admin/users/', views_auth.list_users, name='list-users'),
    path('admin/users/create/', views_auth.create_user, name='create-user'),
    path('admin/users/<int:user_id>/', views_auth.update_user, name='update-user'),
    path('admin/users/<int:user_id>/delete/', views_auth.delete_user, name='delete-user'),
    path('admin/roles/', views_auth.list_roles, name='list-roles'),
    path('admin/audit/', views_auth.get_audit_logs, name='audit-logs'),

    # =================================================================
    # TRAFFIC & DETECTION (accessible based on role)
    # =================================================================
    path('traffic/', views.get_traffic_logs, name='traffic-logs'),
    path('traffic/clear/', views.clear_traffic_logs, name='clear-traffic'),
    path('traffic/count/', views.get_traffic_count, name='traffic-count'),
    path('traffic/<int:log_id>/delete/', views.delete_traffic_log, name='delete-traffic-log'),
    path('traffic/<int:log_id>/acknowledge/', views.acknowledge_traffic_log, name='acknowledge-traffic-log'),
    path('traffic/<int:log_id>/reclassify/', views.reclassify_traffic_log, name='reclassify-traffic-log'),
    path('traffic/<int:log_id>/recheck-llm/', views.recheck_with_llm, name='recheck-llm'),
    path('traffic/<int:log_id>/features/', views.get_traffic_features, name='traffic-features'),

    # ALERTS
    path('alerts/', views.get_alerts, name='alerts'),
    path('alerts/create/', views.create_alert, name='create-alert'),
    path('alerts/clear/', views.clear_alerts, name='clear-alerts'),
    path('attack-groups/', views.get_attack_groups, name='attack-groups'),
    path('diverse-alerts/', views.get_diverse_alerts, name='diverse-alerts'),

    # STATISTICS
    path('stats/', views.get_stats, name='stats'),
    path('stats/protocols/', views.get_protocol_stats, name='protocol-stats'),
    path('stats/top-ips/', views.get_top_ips, name='top-ips'),
    path('stats/attack-types/', views.get_attack_types, name='attack-types'),

    # REPORTS
    path('report/', views.download_report, name='download-report'),
    path('reports/csv/', views.download_csv_report, name='report-csv'),
    path('reports/pdf/', views.download_pdf_report, name='report-pdf'),
    path('reports/json/', views.download_json_report, name='report-json'),
    path('reports/preview/', views.get_report_preview, name='report-preview'),

    # LLM ANALYSIS
    path('analyze/', views.analyze_traffic_llm, name='analyze-traffic'),

    # DETECTION ENGINE SELECTOR
    path('engine/status/', engine_status, name='engine-status'),
    path('engine/select/', engine_select, name='engine-select'),
    path('engine/info/',   engine_info,   name='engine-info'),

    # ZERO-DAY DETECTION (DuckDuckGo + LLM)
    path('zero-day/scan/',   scan_zero_day,   name='zero-day-scan'),
    path('zero-day/recent/', recent_zero_day, name='zero-day-recent'),

    # MODEL RETRAINING
    path('retraining/status/', training_status, name='training-status'),
    path('retraining/history/', training_history, name='training-history'),
    path('retraining/data-stats/', data_stats, name='data-stats'),
    path('retraining/backups/', model_backups, name='backups'),
    path('retraining/start/', start_training, name='start-training'),
    path('retraining/cancel/', cancel_training, name='cancel-training'),
    path('retraining/restore/', restore_backup, name='restore-backup'),
    path('retraining/reset-flags/', reset_flags, name='reset-flags'),

    # DIAGNOSTICS
    path('diagnostics/health/', system_health, name='system-health'),
    path('diagnostics/endpoints/', api_endpoints_status, name='api-endpoints'),
    path('diagnostics/errors/', recent_errors, name='recent-errors'),

    # ERROR LOGGING
    path('errors/', get_system_errors, name='get-errors'),
    path('errors/log/', log_frontend_error, name='log-error'),
    path('errors/resolve/', resolve_error, name='resolve-error'),
    path('errors/clear/', clear_all_errors, name='clear-errors'),
]