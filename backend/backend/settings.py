"""
PIDS - Predictive Intrusion Detection System
Django Settings Configuration
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

# =============================================================================
# SECURITY SETTINGS
# =============================================================================
SECRET_KEY = os.getenv('SECRET_KEY', 'django-insecure-pids-secret-key-change-in-production-2024')
JWT_SECRET = os.getenv('JWT_SECRET') or SECRET_KEY
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
ALLOWED_HOSTS = ['*']

# =============================================================================
# APPLICATION DEFINITION
# =============================================================================
INSTALLED_APPS = [
    # Must be first — replaces runserver with an ASGI/WebSocket-aware one
    'daphne',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third-party apps
    'channels',
    'rest_framework',
    'corsheaders',
    
    # Local apps
    'api',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'api.middleware.ErrorLoggingMiddleware',
    'api.middleware.RateLimitMiddleware',

]

ROOT_URLCONF = 'backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'backend.wsgi.application'

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================
# Check if PostgreSQL credentials are provided, otherwise use SQLite
DB_NAME = os.getenv('DB_NAME')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')

AUTH_USER_MODEL = 'api.CustomUser'

if DB_NAME and DB_USER and DB_PASSWORD:
    # PostgreSQL Configuration
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': DB_NAME,
            'USER': DB_USER,
            'PASSWORD': DB_PASSWORD,
            'HOST': os.getenv('DB_HOST', 'localhost'),
            'PORT': os.getenv('DB_PORT', '5432'),
            'OPTIONS': {
                'connect_timeout': 10,
            },
        }
    }
    print("📦 Using PostgreSQL Database")
else:
    # Fallback to SQLite for development
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }
    print("📦 Using SQLite Database (set DB_NAME, DB_USER, DB_PASSWORD in .env for PostgreSQL)")

# =============================================================================
# PASSWORD VALIDATION
# =============================================================================
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# =============================================================================
# INTERNATIONALIZATION
# =============================================================================
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Karachi'  # Pakistan timezone
USE_I18N = True
USE_TZ = True

# =============================================================================
# STATIC FILES
# =============================================================================
STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# =============================================================================
# DJANGO REST FRAMEWORK
# =============================================================================
REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 100,
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ],
}

# =============================================================================
# CORS SETTINGS
# =============================================================================
CORS_ALLOW_ALL_ORIGINS = True  # Only in development
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://192.168.100.9:3000",
    "http://192.168.100.13:3000",
]
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]

# =============================================================================
# CHANNELS (WebSocket)
# =============================================================================
ASGI_APPLICATION = 'backend.asgi.application'
CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels.layers.InMemoryChannelLayer',
    },
}

# =============================================================================
# ML / DL MODELS CONFIGURATION
# =============================================================================
ML_MODELS_DIR = os.path.join(BASE_DIR, 'ml_models')
DL_MODELS_DIR = os.path.join(BASE_DIR, 'dl_models')

# Default detection engine when both are available. Overridden at runtime
# by EngineConfig (DB singleton). Valid values: 'ml', 'dl'.
DETECTION_ENGINE_DEFAULT = 'dl'

# DL engine: when False (default) apply the same UDP / normal-port
# false-positive heuristics as the ML engine for user-visible consistency.
# When True, DL runs raw (sigmoid threshold + softmax argmax only) — useful
# for fair side-by-side comparison with ML.
DL_RAW_MODE = False

# DL stage-2 was trained on 13 attack classes (Infiltration excluded by
# design — see dl_models/label_mapping.pkl 'infil_label_idx'). Predictions
# below this softmax confidence are routed to the LLM behavioural engine
# for deeper analysis (which can return 'Infilteration', a known class
# name, or 'Unknown').
DL_LOW_CONFIDENCE_THRESHOLD = 0.7

# Toggle the LLM-routing path described above. When False, low-confidence
# DL predictions are returned as-is with status='Suspicious'.
DL_INFIL_ROUTING_ENABLED = True

# =============================================================================
# OLLAMA LLM CONFIGURATION
# =============================================================================
OLLAMA_HOST = os.getenv('OLLAMA_HOST', 'http://localhost:11434')
OLLAMA_MODEL = os.getenv('OLLAMA_MODEL', 'llama3')
LLM_CONFIDENCE_THRESHOLD = 0.5  # Trigger LLM when confidence below this

# When True, the PDF report's prose sections (executive summary,
# recommendations, cover blurb, section intros) are generated by Llama
# at download time. When False (or Ollama unreachable), the report
# falls back to the original static templates — format identical
# either way. Toggleable for the demo without changing code.
LLM_REPORTS_ENABLED = True

# Controls how /api/traffic/<id>/recheck-llm/ behaves:
#   'pure'   — every recheck is fully delegated to Llama. Heuristic
#              short-circuits (multicast clearing, malicious-port
#              preservation, rate-detection preservation, post-LLM
#              feature override) are all skipped; the LLM is given
#              the contextual signals as annotations and decides.
#   'hybrid' — keeps the legacy heuristic gates around the LLM call.
# Frontend can override per request by sending {"mode": "hybrid"}.
LLM_RECHECK_MODE = 'pure'

# =============================================================================
# LOGGING
# =============================================================================
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'api': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}