# Django 로그인 및 회원가입 시스템 README  

## 프로젝트 개요  
이 프로젝트는 Django를 기반으로 한 로그인 및 회원가입 시스템입니다. Docker를 활용하여 쉽게 배포 및 실행할 수 있도록 구성되었습니다.  

## 기술 스택  
- **프레임워크**: Django, Django REST Framework (DRF)  
- **데이터베이스**: PostgreSQL  
- **인증 및 보안**: JWT 인증, 2FA(이중 인증), Django 기본 인증 시스템  
- **비동기 작업 처리**: Celery, Redis  
- **API 문서화**: drf-spectacular (Swagger 지원)  
- **컨테이너화 및 배포**: Docker, Docker Compose  

## 주요 기능  
- 회원가입: 이메일 및 비밀번호를 이용한 사용자 등록  
- 로그인: Django의 인증 시스템을 활용한 로그인  
- 로그아웃: 인증된 사용자 세션 종료  
- JWT 인증: REST API 기반의 인증 시스템 적용  
- 2FA(이중 인증): OTP 기반의 추가 인증 기능 제공  
- 비동기 작업 처리: 이메일 인증, 비밀번호 재설정 등의 작업을 Celery를 활용하여 백그라운드에서 실행  

## 환경 설정 및 실행 방법  

### 1. 필수 요구 사항  
- Docker  
- Docker Compose  

### 2. 프로젝트 실행  

```bash
docker compose up --build -d
```

위 명령어를 실행하면 컨테이너가 생성 및 실행되며, Django 서버가 자동으로 구동됩니다.  

### 3. 환경 변수 설정 (.env 파일)  
`.env` 파일을 프로젝트 루트에 생성하고, 필요한 환경 변수를 설정하세요. 예제:  

```
# ================================
# 환경 설정
# ================================
DEBUG=False
SECRET_KEY= # secret_key 입력
JWT_SIGNING_KEY= # JWT SIGNING KEY
BASE_URL=http://0.0.0.0:8000

# ================================
# 데이터베이스 설정
# ================================
POSTGRES_DB=django_db 
POSTGRES_USER=django_user
POSTGRES_PASSWORD="django0628!"
CONN_MAX_AGE=600

# ================================
# Redis 설정
# ================================
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_DB=0

# ================================
# 호스트 및 보안 설정
# ================================
ALLOWED_HOSTS=0.0.0.0,localhost
CORS_ALLOWED_ORIGINS=
CSRF_TRUSTED_ORIGINS=

# ================================
# OAuth 설정
# ================================
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URI=http://0.0.0.0:8000/api/v1/auth/oauth/google/login/
GOOGLE_TOKEN_URL=https://oauth2.googleapis.com/token
GOOGLE_USER_INFO_URL=https://www.googleapis.com/oauth2/v2/userinfo

GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GITHUB_REDIRECT_URI=http://0.0.0.0:8000/api/v1/auth/oauth/github/callback/
GITHUB_TOKEN_URL=https://github.com/login/oauth/access_token
GITHUB_USER_INFO_URL=https://api.github.com/user

# ================================
# 이메일 설정
# ================================
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=
EMAIL_HOST_PASSWORD=
DEFAULT_FROM_EMAIL=

# ================================
# 스토리지 설정
# ================================

AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_STORAGE_BUCKET_NAME=
AWS_S3_REGION_NAME=ap-northeast-2
AWS_S3_SIGNATURE_VERSION=s3v4
```

## API 엔드포인트  
API에 대한 상세한 설명은 Swagger 문서를 참고하세요.  

[Swagger 문서](http://localhost:8000/api/schema/swagger/)  

## 배포  
프로덕션 환경에서는 `DEBUG=False`로 설정해서 바로 적용하실 수 있습니다.