from pathlib import Path
import os
from datetime import timedelta
import environ

# ================================
# 환경 변수 설정
# ================================

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env(
    DEBUG=(bool, False),
)

env_file = os.path.join(BASE_DIR, '.env')
environ.Env.read_env(env_file)

# ================================
# 기본 설정
# ================================

BASE_URL = env('BASE_URL')
SECRET_KEY = env('SECRET_KEY')
DEBUG = env('DEBUG')
ALLOWED_HOSTS = env('ALLOWED_HOSTS').split(',')
ROOT_URLCONF = 'Auth_Template.urls'
APPEND_SLASH = True

# ================================
# 애플리케이션 설정
# ================================

INSTALLED_APPS = [
    'jazzmin',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'Users',
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'django_celery_beat',
    'drf_spectacular',
    'storages'
]

SITE_ID = 1

# ================================
# 미들웨어 설정
# ================================

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.gzip.GZipMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
]

# ================================
# 데이터베이스 설정
# ================================

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env('POSTGRES_DB'),
        'USER': env('POSTGRES_USER'),
        'PASSWORD': env('POSTGRES_PASSWORD'),
        'HOST': 'postgres',
        'PORT': 5432,
        'CONN_MAX_AGE': env.int('CONN_MAX_AGE'),
        'DISABLE_SERVER_SIDE_CURSORS': True,
        'ATOMIC_REQUESTS': True,
        'OPTIONS': {
            'connect_timeout': 10,
            'application_name': 'django_app',
            'options': (
                '-c statement_timeout=3000ms '
                '-c idle_in_transaction_session_timeout=60000 '
                '-c max_parallel_workers_per_gather=4 '
                '-c effective_cache_size=4GB '
                '-c work_mem=128MB '
                '-c maintenance_work_mem=256MB '
                '-c wal_compression=on '
            ),
        },
    }
}

# ================================
# 인증 설정
# ================================

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 8}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
]

AUTH_USER_MODEL = 'Users.CustomUser'

# ================================
# REST 프레임워크 설정
# ================================

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination',
    'PAGE_SIZE': 50,
    'EXCEPTION_HANDLER': 'Users.custom_exception_handler.custom_exception_handler',
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.JSONParser',
    ],
    'DEFAULT_VERSIONING_CLASS': 'rest_framework.versioning.NamespaceVersioning',
    'DEFAULT_VERSION': 'v1',
    'ALLOWED_VERSIONS': ['v1'],
    'DATETIME_FORMAT': '%Y-%m-%dT%H:%M:%S.%fZ',
}


# ================================
# SWAGGER 설정
# ================================

SPECTACULAR_SETTINGS = {
    'OAS_VERSION': '3.1.0',
    'TITLE': 'Authentication API',
    'DESCRIPTION': 'Authentication API',
    'VERSION': '1.0.0',
    
    'CONTACT': {
        'name': 'Jinwoo Kim',
        'email': 'contact@kimjinwoo.me',
        'url': 'https://blog.kimjinwoo.me',
    },
    'LICENSE': {
        'name': 'MIT License',
        'url': 'https://opensource.org/licenses/MIT',
    },

    'SERVE_PERMISSIONS': ['rest_framework.permissions.AllowAny'],
    'SERVE_AUTHENTICATION': ['rest_framework_simplejwt.authentication.JWTAuthentication'],

    'SWAGGER_UI_SETTINGS': {
        'deepLinking': True,
        'defaultModelRendering': 'example',
        'defaultModelsExpandDepth': 1,
        'defaultModelExpandDepth': 2,
        'persistAuthorization': True,
        'displayRequestDuration': True,
    },
    'REDOC_UI_SETTINGS': {
        'expandResponses': '200,201',
        'hideDownloadButton': False,
    },

    'COMPONENT_SPLIT_REQUEST': True,
    'COMPONENT_NO_READ_ONLY_REQUIRED': True,

    'SORT_OPERATIONS': True,
    'ENUM_NAME_OVERRIDES': {
        'StatusEnum': {
            'OPEN': '열림',
            'CLOSED': '닫힘',
        }
    },

    'SECURITY': [
        {'bearerAuth': []},
    ],

    'DISABLE_ERRORS_AND_WARNINGS': False,
}

# ================================
# JWT 설정
# ================================

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=30),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': env('JWT_SIGNING_KEY'),
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
}

# ================================
# CORS 설정
# ================================

CORS_ALLOWED_ORIGINS = env('CORS_ALLOWED_ORIGINS').split(',')
CORS_ALLOW_CREDENTIALS = True

# ================================
# CSRF 설정
# ================================

CSRF_TRUSTED_ORIGINS = env('CSRF_TRUSTED_ORIGINS').split(',')
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
SECURE_CROSS_ORIGIN_OPENER_POLICY = None

# ================================
# 캐시 설정
# ================================

CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': f'redis://{env("REDIS_HOST")}:{env("REDIS_PORT")}/{env("REDIS_DB")}',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'SOCKET_CONNECT_TIMEOUT': 2,
            'SOCKET_TIMEOUT': 2, 
            'IGNORE_EXCEPTIONS': True,
        },
    }
}


# ================================
# 로깅 설정
# ================================

LOG_DIR = os.path.join(BASE_DIR, 'logs')
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file_error': {
            'level': 'ERROR',
            'class': 'logging.FileHandler',
            'filename': os.path.join(LOG_DIR, 'error.log'),
            'formatter': 'verbose',
        },
        'file_info': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': os.path.join(LOG_DIR, 'info.log'),
            'formatter': 'verbose',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file_error', 'file_info','console'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}

# ================================
# i18n 및 시간 설정
# ================================

LANGUAGE_CODE = 'ko-kr'
TIME_ZONE = 'Asia/Seoul'
USE_I18N = True
USE_TZ = True

# ================================
# 템플릿 설정
# ================================

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

# ================================
# Celery 설정
# ================================

CELERY_BROKER_URL = f'redis://{env("REDIS_HOST")}:{env("REDIS_PORT")}/0'
CELERY_RESULT_BACKEND = f'redis://{env("REDIS_HOST")}:{env("REDIS_PORT")}/1'

CELERY_BROKER_TRANSPORT_OPTIONS = {
    'visibility_timeout': 3600,
    'max_connections': 100,
}

CELERY_ACCEPT_CONTENT = ['json', 'msgpack']
CELERY_TASK_SERIALIZER = 'msgpack'
CELERY_RESULT_SERIALIZER = 'msgpack'
CELERY_MESSAGE_COMPRESSION = 'zlib'
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 300
CELERY_TASK_SOFT_TIME_LIMIT = 270
CELERY_WORKER_PREFETCH_MULTIPLIER = 4
CELERY_WORKER_MAX_TASKS_PER_CHILD = 100
CELERY_WORKER_CONCURRENCY = 4
CELERY_TIMEZONE = 'Asia/Seoul'
CELERY_ENABLE_UTC = False
CELERY_SEND_EVENTS = True
CELERY_TASK_SEND_SENT_EVENT = True
CELERY_WORKER_HIJACK_ROOT_LOGGER = False


# ================================
# 기본 자동 필드 설정
# ================================

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ================================
# 실시간 채널 설정
# ================================

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [(env("REDIS_HOST"), int(env("REDIS_PORT")))],
        },
    },
}
ASGI_APPLICATION = 'Auth_Template.asgi.application'

# ================================
# OAuth 설정
# ================================

GOOGLE_CLIENT_ID = env('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = env('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = env('GOOGLE_REDIRECT_URI')
GOOGLE_TOKEN_URL = env('GOOGLE_TOKEN_URL')
GOOGLE_USER_INFO_URL = env('GOOGLE_USER_INFO_URL')

GITHUB_CLIENT_ID = env('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = env('GITHUB_CLIENT_SECRET')
GITHUB_REDIRECT_URI = env('GITHUB_REDIRECT_URI')
GITHUB_TOKEN_URL = env('GITHUB_TOKEN_URL')
GITHUB_USER_INFO_URL = env('GITHUB_USER_INFO_URL')

# ================================
# 이메일 설정
# ================================

EMAIL_BACKEND = env('EMAIL_BACKEND')
EMAIL_HOST = env('EMAIL_HOST')
EMAIL_PORT = env.int('EMAIL_PORT')
EMAIL_USE_TLS = env.bool('EMAIL_USE_TLS')
EMAIL_HOST_USER = env('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = env('DEFAULT_FROM_EMAIL')

# ================================
# GEOIP 설정
# ================================

GEOIP_PATH = os.path.join(BASE_DIR, "GeoLite2-City.mmdb")

# ================================
# 스토리지 설정
# ================================

STORAGES = {
    "default": {
        "BACKEND": "storages.backends.s3boto3.S3Boto3Storage",
        "OPTIONS": {
            "access_key": env("AWS_ACCESS_KEY_ID"),
            "secret_key": env("AWS_SECRET_ACCESS_KEY"),
            "bucket_name": env("AWS_STORAGE_BUCKET_NAME"),
            "region_name": env("AWS_S3_REGION_NAME"),
            # "default_acl": "public-read",
            "querystring_auth": False,
        },
    },
    "staticfiles": {
        "BACKEND": "storages.backends.s3boto3.S3StaticStorage",
        "OPTIONS": {
            "access_key": env("AWS_ACCESS_KEY_ID"),
            "secret_key": env("AWS_SECRET_ACCESS_KEY"),
            "bucket_name": env("AWS_STORAGE_BUCKET_NAME"),
            "region_name": env("AWS_S3_REGION_NAME"),
            # "default_acl": "public-read",
        },
    },
}

# ================================
# 정적 파일 경로 설정
# ================================

STATIC_URL = f"https://{env('AWS_STORAGE_BUCKET_NAME')}.s3.{env('AWS_S3_REGION_NAME')}.amazonaws.com/static/"
MEDIA_URL = f"https://{env('AWS_STORAGE_BUCKET_NAME')}.s3.{env('AWS_S3_REGION_NAME')}.amazonaws.com/media/"
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')