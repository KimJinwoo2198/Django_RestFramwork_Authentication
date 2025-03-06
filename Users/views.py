import logging
import random
from io import BytesIO
from urllib.parse import urlencode
import base64
import requests
import pyotp
import qrcode

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework import serializers

from django.db import transaction
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone, crypto

from .serializers import (
    CustomUserCreationSerializer,
    CustomAuthTokenSerializer,
    CallbackUserInfoSerializer,
    Verify2FASerializer,
    Disable2FASerializer,
    StartEnable2FASerializer,
    EmailVerificationSerializer,
    TokenRefreshSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer
)
from .exceptions import (
    AccountLockedException,
    TooManyAttemptsException,
    GoogleAPIError,
    UserCreationError
)
from .models import (
    EmailVerification,
    LoginHistory
)
from .tasks import (
    send_verification_email,
    get_location_from_ip,
    LoginHistoryTask,
    send_password_reset_email
)
from .utils import parse_user_agent

from drf_spectacular.utils import (
    extend_schema,
    OpenApiResponse,
    OpenApiExample,
    OpenApiParameter
)
from drf_spectacular.types import OpenApiTypes

logger = logging.getLogger(__name__)
User = get_user_model()

class SignupViewSet(viewsets.GenericViewSet):
    permission_classes = [AllowAny]
    serializer_class = CustomUserCreationSerializer

    @extend_schema(
        summary="회원가입",
        description="새로운 사용자를 등록합니다.",
        request=CustomUserCreationSerializer,
        responses={
            201: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="회원가입 성공",
                examples=[
                    OpenApiExample(
                        "회원가입 성공",
                        value={
                            "status": "success",
                            "code": 201,
                            "message": "회원가입이 완료되었습니다. 이메일로 전송된 인증번호를 입력해주세요.",
                            "data": {"user_id": 1},
                            "meta": {"timestamp": "2024-12-11T08:42:59.754719+00:00"}
                        },
                    )
                ]
            ),
            400: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="잘못된 입력",
                examples=[
                    OpenApiExample(
                        "잘못된 입력",
                        value={
                            "status": "error",
                            "code": 400,
                            "message": "입력 데이터가 유효하지 않습니다.",
                            "errors": {
                                "username": ["이미 사용 중인 사용자 이름입니다."],
                                "email": ["이미 등록된 이메일 주소입니다."],
                                "password": ["비밀번호가 너무 짧습니다. 최소 8자 이상이어야 합니다."],
                                "phone_number": ["올바른 전화번호 형식이 아닙니다. 예: 010-1234-5678"]
                            },
                            "meta": {"timestamp": "2024-12-11T08:35:21.408328+00:00"}
                        },
                    )
                ]
            ),
            500: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="서버 에러",
                examples=[
                    OpenApiExample(
                        "서버 에러",
                        value={
                            "status": "error",
                            "code": 500,
                            "message": "회원가입 중 오류가 발생했습니다. 다시 시도해주세요.",
                            "errors": ["내부 서버 오류가 발생했습니다."],
                            "meta": {"timestamp": "2024-12-11T08:37:27.677216+00:00"}
                        },
                    )
                ]
            ),
        },
        tags=["Authentication"]
    )
    @action(detail=False, methods=['post'], url_path='signup')
    def create_account(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save()
                verification_code = str(random.randint(100000, 999999))
                EmailVerification.objects.create(user=user, code=verification_code)
                send_verification_email.delay(user.email, verification_code)
                
                return Response({
                    "status": "success",
                    "code": 201,
                    "message": "회원가입이 완료되었습니다. 이메일로 전송된 인증번호를 입력해주세요.",
                    "data": {"user_id": user.id},
                    "meta": {"timestamp": timezone.now().isoformat()}
                }, status=status.HTTP_201_CREATED)
            except Exception as e:
                logger.error(f"회원가입 중 오류 발생: {str(e)}")
                return Response({
                    "status": "error",
                    "code": 500,
                    "message": "회원가입 중 오류가 발생했습니다. 다시 시도해주세요.",
                    "errors": [str(e)],
                    "meta": {"timestamp": timezone.now().isoformat()}
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({
                "status": "error",
                "code": 400,
                "message": "입력 데이터가 유효하지 않습니다.",
                "errors": serializer.errors,
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmailViewSet(viewsets.GenericViewSet):
    permission_classes = [AllowAny]
    serializer_class = EmailVerificationSerializer

    @extend_schema(
        summary="이메일 인증",
        description="사용자가 받은 이메일 인증번호를 검증합니다.",
        request=EmailVerificationSerializer,
        responses={
            200: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="인증 성공",
                examples=[
                    OpenApiExample(
                        "인증 성공",
                        value={
                            "status": "success", 
                            "code": 200,
                            "message": "이메일 인증이 완료되었습니다.",
                            "data": {
                                "email": "user@example.com",
                                "is_verified": True,
                                "verified_at": "2024-12-11T08:42:59.754719+00:00"
                            },
                            "meta": {"timestamp": "2024-12-11T08:42:59.754719+00:00"}
                        }
                    )
                ]
            ),
            400: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="인증 실패",
                examples=[
                    OpenApiExample(
                        "유효성 검증 실패",
                        value={
                            "status": "error",
                            "code": 400,
                            "message": "입력 데이터가 유효하지 않습니다.",
                            "errors": {
                                "email": ["올바른 이메일 형식이 아닙니다."],
                                "verification_code": ["인증코드는 6자리 숫자여야 합니다."]
                            },
                            "meta": {"timestamp": "2024-12-11T08:35:21.408328+00:00"}
                        }
                    )
                ]
            ),
            500: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="서버 에러",
                examples=[
                    OpenApiExample(
                        "서버 에러",
                        value={
                            "status": "error",
                            "code": 500,
                            "message": "이메일 인증 중 오류가 발생했습니다.",
                            "errors": ["내부 서버 오류가 발생했습니다."],
                            "meta": {"timestamp": "2024-12-11T08:37:27.677216+00:00"}
                        }
                    )
                ]
            ),
        },
        tags=["Authentication"]
    )
    @action(detail=False, methods=['post'])
    def verify(self, request):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            
            verification = serializer.validated_data['verification']
            user = verification.user
            
            with transaction.atomic():
                user.is_active = True
                user.save()
                
                verification.is_used = True
                verification.attempts += 1
                verification.save()
                
            return Response({
                "status": "success",
                "code": 200,
                "message": "이메일 인증이 완료되었습니다.",
                "data": serializer.to_representation(serializer.validated_data),
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_200_OK)

        except serializers.ValidationError as e:
            return Response({
                "status": "error",
                "code": 400,
                "message": "입력 데이터가 유효하지 않습니다.",
                "errors": e.detail,
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f"이메일 인증 중 오류 발생: {str(e)}")
            return Response({
                "status": "error", 
                "code": 500,
                "message": "이메일 인증 중 오류가 발생했습니다.",
                "errors": ["내부 서버 오류가 발생했습니다."],
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LoginViewSet(viewsets.GenericViewSet):
    permission_classes = [AllowAny]
    serializer_class = CustomAuthTokenSerializer

    @extend_schema(
        summary="로그인",
        description="사용자 로그인 및 JWT 토큰 발급",
        request=CustomAuthTokenSerializer,
        parameters=[
            OpenApiParameter(
                name="X-Forwarded-For",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.HEADER,
                description="요청 클라이언트의 IP 주소를 지정합니다.",
                required=False,
            )
        ],
        responses={
            200: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="로그인 성공",
                examples=[
                    OpenApiExample(
                        "로그인 성공",
                        value={
                            "status": "success",
                            "code": 200,
                            "message": "로그인에 성공했습니다.",
                            "data": {
                                "tokens": {"refresh": "...", "access": "..."}
                            },
                            "meta": {"timestamp": "2024-12-11T08:42:59.754719+00:00"}
                        },
                    )
                ]
            ),
            202: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="2차 인증 필요",
                examples=[
                    OpenApiExample(
                        "2차 인증 필요",
                        value={
                            "status": "success",
                            "code": 202,
                            "message": "로그인 성공. 2차 인증 토큰을 입력하세요.",
                            "data": {"user": {"id": 1}},
                            "meta": {"timestamp": "2024-12-11T08:48:21.001880+00:00"}
                        },
                    )
                ]
            ),
            400: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="잘못된 입력",
                examples=[
                    OpenApiExample(
                        "잘못된 입력",
                        value={
                            "status": "error",
                            "code": 400,
                            "message": "필수 필드가 누락되었습니다. 필드를 확인하고 다시 시도하세요.",
                            "error_code": "missing_field",
                            "meta": {"timestamp": "2024-12-11T08:35:21.408328+00:00"}
                        },
                    )
                ]
            ),
            401: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="인증 실패",
                examples=[
                    OpenApiExample(
                        "인증 실패",
                        value={
                            "status": "error",
                            "code": 401,
                            "message": "아이디 또는 비밀번호가 잘못되었습니다.",
                            "error_code": "invalid_credentials",
                            "meta": {"timestamp": "2024-12-11T08:35:21.408328+00:00"}
                        },
                    )
                ]
            ),
            429: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="과도한 로그인 시도",
                examples=[
                    OpenApiExample(
                        "과도한 로그인 시도",
                        value={
                            "status": "error",
                            "code": 429,
                            "message": "로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요.",
                            "error_code": "too_many_attempts",
                            "meta": {"timestamp": "2024-12-11T08:37:27.677216+00:00"}
                        },
                    )
                ]
            ),
        },
        tags=["Authentication"]
    )
    @action(detail=False, methods=['post'])
    def login(self, request, *args, **kwargs):
        ip = self.get_client_ip(request)
        location_result = get_location_from_ip.delay(ip)
        login_attempts = cache.get(f'login_attempts_{ip}', 0)

        if login_attempts >= 10:
            ttl = cache.ttl(f'login_attempts_{ip}')
            if ttl is None or ttl > 0:
                raise TooManyAttemptsException()
            else:
                cache.set(f'login_attempts_{ip}', 0)

        serializer = self.get_serializer(data=request.data, context={'request': request})
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']

            if user.is_2fa_enabled:
                return Response({
                    "status": "success",
                    "code": status.HTTP_202_ACCEPTED,
                    "message": "로그인 성공. 2차 인증 토큰을 입력하세요.",
                    "data": {"user": {"id": user.id}},
                    "meta": {"timestamp": timezone.now().isoformat()}
                }, status=status.HTTP_202_ACCEPTED)

            user_agent = request.META.get('HTTP_USER_AGENT', '')
            location = location_result.get(timeout=10)
            
            LoginHistoryTask.delay(user_id=user.id, ip=ip, user_agent=user_agent, success=True, location=location)
                
            cache.delete(f'login_attempts_{ip}')
            refresh = RefreshToken.for_user(user)

            return Response({
                "status": "success",
                "code": status.HTTP_200_OK,
                "message": "로그인에 성공했습니다.",
                "data": {
                    "tokens": {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token)
                    }
                },
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_200_OK)
        except Exception as e:
            cache.set(f'login_attempts_{ip}', login_attempts + 1, 300)
            try:
                user_agent = request.META.get('HTTP_USER_AGENT', '')
                location = location_result.get(timeout=10)
                LoginHistoryTask.delay(user_id=None, ip=ip, user_agent=user_agent, success=False, location=location)
            except:
                pass
            logger.warning("Failed login attempt for username: %s, IP: %s", request.data.get('username'), ip)
            raise

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip

    def is_new_location(self, user, location):
        recent_logins = LoginHistory.objects.filter(
            user=user, success=True
        ).order_by('-login_time').only('location')[:5]
        recent_locations = [login.location for login in recent_logins]
        return location not in recent_locations

class GoogleLoginViewSet(viewsets.GenericViewSet):
    permission_classes = [AllowAny]

    @extend_schema(
        summary="Google 로그인 URL 생성",
        description="Google OAuth2 로그인 프로세스를 시작하기 위한 URL을 생성합니다.",
        responses={
            200: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="성공적으로 URL 생성",
                examples=[
                    OpenApiExample(
                        "성공적으로 URL 생성",
                        value={
                            "status": "success",
                            "code": 200,
                            "message": "Google 로그인 URL이 성공적으로 생성되었습니다.",
                            "data": {"login_url": "https://..."},
                            "meta": {"timestamp": "2024-12-11T08:42:59.754719+00:00"}
                        }
                    )
                ]
            )
        },
        tags=["Authentication"]
    )
    @action(detail=False, methods=["get"], url_path='login')
    def google_start(self, request):
        google_login_url = "https://accounts.google.com/o/oauth2/v2/auth"
        
        params = {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": "email profile",
            "access_type": "offline",
            "prompt": "select_account"
        }
        
        auth_url = f"{google_login_url}?{urlencode(params)}"
        
        return Response({
            "status": "success",
            "code": 200,
            "message": "Google 로그인 URL이 성공적으로 생성되었습니다.",
            "data": {"login_url": auth_url},
            "meta": {"timestamp": timezone.now().isoformat()}
        })

class GoogleCallbackViewSet(viewsets.GenericViewSet):
    permission_classes = [AllowAny]

    @extend_schema(
        summary="Google OAuth 콜백",
        description="Google OAuth 콜백을 처리하고 사용자 인증을 수행합니다.",
        request=CallbackUserInfoSerializer,
        responses={
            200: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="인증 성공",
                examples=[
                    OpenApiExample(
                        "인증 성공",
                        value={
                            "status": "success",
                            "code": 200,
                            "message": "Google OAuth 인증이 성공적으로 완료되었습니다.",
                            "data": {
                                "access_token": "...",
                                "refresh_token": "...",
                                "user": {
                                    "id": 1,
                                    "email": "user@example.com",
                                    "is_new_user": True
                                }
                            },
                            "meta": {"timestamp": "2024-12-11T08:42:59.754719+00:00"}
                        }
                    )
                ]
            ),
            400: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="잘못된 요청",
                examples=[
                    OpenApiExample(
                        "잘못된 요청",
                        value={
                            "status": "error",
                            "code": 400,
                            "message": "Google OAuth 인증 코드가 필요합니다.",
                            "error_code": "missing_authorization_code",
                            "meta": {"timestamp": "2024-12-11T08:35:21.408328+00:00"}
                        }
                    )
                ]
            ),
            401: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="Google API 인증 실패",
                examples=[
                    OpenApiExample(
                        "Google API 인증 실패",
                        value={
                            "status": "error",
                            "code": 401,
                            "message": "Google API 호출에 실패했습니다.",
                            "error_code": "google_api_error",
                            "meta": {"timestamp": "2024-12-11T08:37:27.677216+00:00"}
                        }
                    )
                ]
            ),
            500: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="서버 내부 오류",
                examples=[
                    OpenApiExample(
                        "서버 내부 오류",
                        value={
                            "status": "error",
                            "code": 500,
                            "message": "예상치 못한 오류가 발생했습니다.",
                            "error_code": "unexpected_error",
                            "meta": {"timestamp": "2024-12-11T08:37:27.677216+00:00"}
                        }
                    )
                ]
            ),
        },
        tags=["Authentication"]
    )
    @action(detail=False, methods=['get'], url_path='callback')
    def google_callback(self, request):
        try:
            code = request.query_params.get('code')
            if not code:
                return Response({
                    "status": "error",
                    "code": 400,
                    "message": "Google OAuth 인증 코드가 필요합니다.",
                    "error_code": "missing_authorization_code",
                    "meta": {"timestamp": timezone.now().isoformat()}
                }, status=status.HTTP_400_BAD_REQUEST)

            google_user = self.get_google_user(code)
            user, is_new_user = self.get_or_create_user(google_user)
            tokens = self.get_tokens_for_user(user)

            return Response({
                "status": "success",
                "code": 200,
                "message": "Google OAuth 인증이 성공적으로 완료되었습니다.",
                "data": {
                    "access_token": tokens['access'],
                    "refresh_token": tokens['refresh'],
                    "user": {"id": user.id, "email": user.email, "is_new_user": is_new_user}
                },
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_200_OK)

        except GoogleAPIError as e:
            logger.error(f"Google API error: {str(e)}")
            return Response({
                "status": "error",
                "code": 401,
                "message": "Google API 호출에 실패했습니다.",
                "error_code": "google_api_error",
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_401_UNAUTHORIZED)
        except UserCreationError as e:
            logger.error(f"User creation error: {str(e)}")
            return Response({
                "status": "error",
                "code": 400,
                "message": str(e),
                "error_code": "user_creation_error",
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.exception("Unexpected error in Google callback")
            return Response({
                "status": "error",
                "code": 500,
                "message": "예상치 못한 오류가 발생했습니다.",
                "error_code": "unexpected_error",
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_google_user(self, code):
        token = self.get_google_token(code)
        user_info = self.get_google_user_info(token)
        return user_info

    def get_google_token(self, code):
        data = {
            'code': code,
            'client_id': settings.GOOGLE_CLIENT_ID,
            'client_secret': settings.GOOGLE_CLIENT_SECRET,
            'redirect_uri': settings.GOOGLE_REDIRECT_URI,
            'grant_type': 'authorization_code'
        }
        response = requests.post(settings.GOOGLE_TOKEN_URL, data=data, timeout=10)
        if response.status_code != 200:
            raise GoogleAPIError("Failed to obtain access token from Google")
        return response.json().get('access_token')

    def get_google_user_info(self, access_token):
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(settings.GOOGLE_USER_INFO_URL, headers=headers, timeout=10)
        if response.status_code != 200:
            raise GoogleAPIError("Failed to get user info from Google")
        return response.json()

    @transaction.atomic
    def get_or_create_user(self, google_user):
        email = google_user.get('email')
        if not email:
            raise UserCreationError("Email is required.")

        google_id = google_user.get('id')
        if not google_id:
            raise UserCreationError("Google user ID is required.")

        is_new_user = False

        try:
            user = User.objects.get(email=email)
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
        except User.DoesNotExist:
            try:
                with transaction.atomic():
                    user = User.objects.create_user(
                        username=email,
                        email=email,
                        first_name=google_user.get('given_name', ''),
                        last_name=google_user.get('family_name', ''),
                        social_id=f"google_{google_id}",
                        social_account_type='google'
                    )
                    is_new_user = True
            except ValidationError as ve:
                raise UserCreationError(f"Validation error: {ve}")
            except Exception as e:
                raise UserCreationError(f"Unexpected error: {e}")

        return user, is_new_user

    def get_tokens_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return {'refresh': str(refresh), 'access': str(refresh.access_token)}

class GitHubLoginViewSet(viewsets.GenericViewSet):
    permission_classes = [AllowAny]

    @extend_schema(
        summary="GitHub 로그인 URL 생성",
        description="GitHub OAuth2 로그인 프로세스를 시작하기 위한 URL을 생성합니다.",
        responses={
            200: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="성공적으로 URL 생성",
                examples=[
                    OpenApiExample(
                        "성공적으로 URL 생성",
                        value={
                            "status": "success",
                            "code": 200,
                            "message": "GitHub 로그인 URL이 성공적으로 생성되었습니다.",
                            "data": {"login_url": "https://github.com/login/oauth/authorize?..."},
                            "meta": {"timestamp": "2024-12-11T08:42:59.754719+00:00"}
                        }
                    )
                ]
            )
        },
        tags=["Authentication"]
    )
    @action(detail=False, methods=["get"], url_path='login')
    def github_start(self, request):
        github_login_url = "https://github.com/login/oauth/authorize"
        
        params = {
            "client_id": settings.GITHUB_CLIENT_ID,
            "redirect_uri": settings.GITHUB_REDIRECT_URI,
            "scope": "read:user user:email",
            "allow_signup": "true"
        }
        
        auth_url = f"{github_login_url}?{urlencode(params)}"
        
        return Response({
            "status": "success",
            "code": 200,
            "message": "GitHub 로그인 URL이 성공적으로 생성되었습니다.",
            "data": {"login_url": auth_url},
            "meta": {"timestamp": timezone.now().isoformat()}
        })

class GitHubCallbackViewSet(viewsets.GenericViewSet):
    permission_classes = [AllowAny]

    @extend_schema(
        summary="GitHub OAuth 콜백",
        description="GitHub OAuth 콜백을 처리하고 사용자를 인증합니다.",
        responses={
            200: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="인증 성공",
                examples=[
                    OpenApiExample(
                        "인증 성공",
                        value={
                            "status": "success",
                            "code": 200,
                            "message": "GitHub OAuth 인증이 성공적으로 완료되었습니다.",
                            "data": {
                                "access_token": "JWT_ACCESS_TOKEN",
                                "refresh_token": "JWT_REFRESH_TOKEN",
                                "user": {
                                    "id": 1,
                                    "email": "user@example.com",
                                    "username": "github_username",
                                    "is_new_user": True,
                                },
                            },
                            "meta": {"timestamp": "2025-01-27T08:00:00.000Z"},
                        },
                    )
                ],
            ),
            400: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="잘못된 요청",
                examples=[
                    OpenApiExample(
                        "인증 코드 누락",
                        value={
                            "status": "error",
                            "code": 400,
                            "message": "GitHub OAuth 인증 코드가 필요합니다.",
                            "meta": {"timestamp": "2025-01-27T08:00:00.000Z"},
                        },
                    )
                ],
            ),
            500: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="서버 내부 오류",
                examples=[
                    OpenApiExample(
                        "서버 내부 오류",
                        value={
                            "status": "error",
                            "code": 500,
                            "message": "예상치 못한 오류가 발생했습니다.",
                            "meta": {"timestamp": "2025-01-27T08:00:00.000Z"},
                        },
                    )
                ],
            ),
        },
        tags=["Authentication"],
    )
    @action(detail=False, methods=["get"], url_path="callback")
    def github_callback(self, request):
        try:
            code = request.query_params.get("code")
            if not code:
                return Response(
                    {
                        "status": "error",
                        "code": 400,
                        "message": "GitHub OAuth 인증 코드가 필요합니다.",
                        "meta": {"timestamp": timezone.now().isoformat()},
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )
            access_token = self.get_github_access_token(code)
            user_data = self.get_github_user_data(access_token)
            user, is_new_user = self.get_or_create_user(user_data)
            tokens = self.get_tokens_for_user(user)

            return Response(
                {
                    "status": "success",
                    "code": 200,
                    "message": "GitHub OAuth 인증이 성공적으로 완료되었습니다.",
                    "data": {
                        "access_token": tokens["access"],
                        "refresh_token": tokens["refresh"],
                        "user": {
                            "id": user.id,
                            "email": user.email,
                            "username": user.username,
                            "is_new_user": is_new_user,
                        },
                    },
                    "meta": {"timestamp": timezone.now().isoformat()},
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.exception("GitHub OAuth 처리 중 오류 발생")
            return Response(
                {
                    "status": "error",
                    "code": 500,
                    "message": "예상치 못한 오류가 발생했습니다.",
                    "meta": {"timestamp": timezone.now().isoformat()},
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def get_github_access_token(self, code):
        response = requests.post(
            settings.GITHUB_TOKEN_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": settings.GITHUB_REDIRECT_URI,
            },
            timeout=10,
        )
        if response.status_code != 200:
            logger.error(f"GitHub 액세스 토큰 요청 실패: {response.text}")
            raise Exception("GitHub 액세스 토큰 요청에 실패했습니다.")
        return response.json().get("access_token")

    def get_github_user_data(self, access_token):
        response = requests.get(
            settings.GITHUB_USER_INFO_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github+json",
            },
            timeout=10,
        )
        if response.status_code != 200:
            raise Exception("GitHub 사용자 정보 요청에 실패했습니다.")
        return response.json()

    def get_or_create_user(self, user_data):
        username = user_data.get("login")
        is_new_user = False
        user = None

        try:
            user = User.objects.get(email=user_data.get("email", ""))
        except User.DoesNotExist:
            user = User.objects.create_user(
                username=username,
                email=user_data.get("email", ""),
                first_name=user_data.get("name", ""),
                social_id=f"github_{user_data.get('id')}",
                social_account_type="github",
            )
            is_new_user = True

        return user, is_new_user

    def get_tokens_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return {"refresh": str(refresh), "access": str(refresh.access_token)}

class StartEnable2FAViewSet(viewsets.GenericViewSet):
    serializer_class = StartEnable2FASerializer
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="2FA 활성화 시작",
        description="2FA를 활성화하기 위해 OTP 비밀 키와 QR 코드를 생성하여 반환합니다.",
        request=StartEnable2FASerializer,
        responses={
            200: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="2FA 활성화 시작 성공",
                examples=[
                    OpenApiExample(
                        "2FA 활성화 시작 성공",
                        value={
                            "status": "success",
                            "code": 200,
                            "message": "2FA 활성화를 시작합니다. QR 코드를 사용하여 인증 앱을 설정하세요.",
                            "data": {
                                "otp_secret": "BASE32SECRET",
                                "qr_code": "base64_image_string"
                            },
                            "meta": {"timestamp": "2024-12-11T08:42:59.754719+00:00"}
                        }
                    )
                ]
            ),
            400: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="2FA 활성화 실패",
                examples=[
                    OpenApiExample(
                        "2FA 활성화 실패",
                        value={
                            "status": "error",
                            "code": 400,
                            "message": "2FA가 이미 활성화되어 있습니다.",
                            "error_code": "already_enabled",
                            "meta": {"timestamp": "2024-12-11T08:35:21.408328+00:00"}
                        }
                    )
                ]
            ),
        },
        tags=["Authentication"]
    )
    @action(detail=False, methods=['post'], url_path='enable')
    def start(self, request):
        user = request.user

        if user.is_2fa_enabled:
            return Response({
                "status": "error",
                "code": 400,
                "message": "2FA가 이미 활성화되어 있습니다.",
                "error_code": "already_enabled",
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_400_BAD_REQUEST)

        user.otp_secret = pyotp.random_base32()
        user.save(update_fields=['otp_secret'])

        otpauth_url = pyotp.TOTP(user.otp_secret).provisioning_uri(user.username, issuer_name="MyApp")
        qr = qrcode.make(otpauth_url)
        qr_io = BytesIO()
        qr.save(qr_io, 'PNG')
        qr_io.seek(0)
        qr_base64 = base64.b64encode(qr_io.getvalue()).decode()

        return Response({
            "status": "success",
            "code": 200,
            "message": "2FA 활성화를 시작합니다. QR 코드를 사용하여 인증 앱을 설정하세요.",
            "data": {"otp_secret": user.otp_secret, "qr_code": qr_base64},
            "meta": {"timestamp": timezone.now().isoformat()}
        }, status=status.HTTP_200_OK)

class VerifyEnable2FAViewSet(viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="2FA 활성화 확인",
        description="사용자가 입력한 OTP를 검증하여 2FA를 활성화합니다.",
        request={
            "type": "object",
            "properties": {
                "otp": {
                    "type": "string",
                    "description": "사용자가 입력한 OTP"
                }
            },
            "required": ["otp"]
        },
        responses={
            200: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="2FA 활성화 성공",
                examples=[
                    OpenApiExample(
                        "2FA 활성화 성공",
                        value={
                            "status": "success",
                            "code": 200,
                            "message": "2FA가 성공적으로 활성화되었습니다.",
                            "data": {},
                            "meta": {"timestamp": "2024-12-11T08:42:59.754719+00:00"}
                        }
                    )
                ]
            ),
            400: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="OTP 검증 실패",
                examples=[
                    OpenApiExample(
                        "OTP 검증 실패",
                        value={
                            "status": "error",
                            "code": 400,
                            "message": "OTP가 유효하지 않습니다.",
                            "error_code": "invalid_otp",
                            "meta": {"timestamp": "2024-12-11T08:35:21.408328+00:00"}
                        }
                    )
                ]
            ),
        },
        tags=["Authentication"]
    )
    @action(detail=False, methods=['post'])
    def verify(self, request):
        user = request.user
        otp = request.data.get('otp')

        if not user.otp_secret:
            return Response({
                "status": "error",
                "code": 400,
                "message": "2FA 활성화를 먼저 시작하세요.",
                "error_code": "not_started",
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_400_BAD_REQUEST)

        totp = pyotp.TOTP(user.otp_secret)
        if not totp.verify(otp):
            return Response({
                "status": "error",
                "code": 400,
                "message": "OTP가 유효하지 않습니다.",
                "error_code": "invalid_otp",
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_400_BAD_REQUEST)

        user.is_2fa_enabled = True
        user.save(update_fields=['is_2fa_enabled'])

        return Response({
            "status": "success",
            "code": 200,
            "message": "2FA가 성공적으로 활성화되었습니다.",
            "data": {},
            "meta": {"timestamp": timezone.now().isoformat()}
        }, status=status.HTTP_200_OK)

class Verify2FAViewSet(viewsets.GenericViewSet):
    permission_classes = [AllowAny]
    serializer_class = Verify2FASerializer

    @extend_schema(
        summary="2차인증 확인",
        description="사용자의 2차 인증 토큰을 검증합니다.",
        request=Verify2FASerializer,
        responses={
            200: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="2FA 인증 성공",
                examples=[
                    OpenApiExample(
                        "2FA 인증 성공",
                        value={
                            "status": "success",
                            "code": 200,
                            "message": "2FA 인증이 성공적으로 완료되었습니다.",
                            "data": {
                                "tokens": {
                                    "refresh": "...",
                                    "access": "..."
                                }
                            },
                            "meta": {"timestamp": "2024-12-11T08:42:59.754719+00:00"}
                        }
                    )
                ]
            ),
            400: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="잘못된 요청",
                examples=[
                    OpenApiExample(
                        "잘못된 요청",
                        value={
                            "status": "error",
                            "code": 400,
                            "message": "유효하지 않은 2FA 토큰입니다.",
                            "error_code": "invalid_2fa_token",
                            "meta": {"timestamp": "2024-12-11T08:35:21.408328+00:00"}
                        }
                    )
                ]
            ),
            404: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="사용자를 찾을 수 없음",
                examples=[
                    OpenApiExample(
                        "사용자를 찾을 수 없음",
                        value={
                            "status": "error",
                            "code": 404,
                            "message": "사용자를 찾을 수 없습니다.",
                            "error_code": "user_not_found",
                            "meta": {"timestamp": "2024-12-11T08:37:27.677216+00:00"}
                        }
                    )
                ]
            ),
            500: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="서버 내부 오류",
                examples=[
                    OpenApiExample(
                        "서버 내부 오류",
                        value={
                            "status": "error",
                            "code": 500,
                            "message": "예상치 못한 오류가 발생했습니다.",
                            "error_code": "unexpected_error",
                            "meta": {"timestamp": "2024-12-11T08:37:27.677216+00:00"}
                        }
                    )
                ]
            ),
        },
        tags=["Authentication"]
    )
    @action(detail=False, methods=['post'])
    def verify(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data, context={'request': request})
            serializer.is_valid(raise_exception=True)

            user = request.user
            refresh = RefreshToken.for_user(user)

            return Response({
                "status": "success",
                "code": 200,
                "message": "2FA 인증이 성공적으로 완료되었습니다.",
                "data": {
                    "tokens": {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token)
                    }
                },
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_200_OK)
        except serializers.ValidationError as e:
            return Response({
                "status": "error",
                "code": 400,
                "message": e.detail,
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_400_BAD_REQUEST)

class Disable2FAViewSet(viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = Disable2FASerializer

    @extend_schema(
        summary="2FA 비활성화",
        description="사용자가 입력한 OTP를 검증하고 2FA를 비활성화합니다.",
        request=Disable2FASerializer,
        responses={
            200: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="2FA 비활성화 성공",
                examples=[
                    OpenApiExample(
                        "2FA 비활성화 성공",
                        value={
                            "status": "success",
                            "code": 200,
                            "message": "2FA가 성공적으로 비활성화되었습니다.",
                            "data": {},
                            "meta": {"timestamp": "2024-12-11T08:42:59.754719+00:00"}
                        }
                    )
                ]
            ),
            400: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="OTP 검증 실패",
                examples=[
                    OpenApiExample(
                        "OTP 검증 실패",
                        value={
                            "status": "error",
                            "code": 400,
                            "message": "OTP가 유효하지 않습니다.",
                            "error_code": "invalid_otp",
                            "meta": {"timestamp": "2024-12-11T08:35:21.408328+00:00"}
                        }
                    )
                ]
            ),
        },
        tags=["Authentication"]
    )
    @action(detail=False, methods=['post'])
    def disable(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user

        user.is_2fa_enabled = False
        user.otp_secret = None
        user.save(update_fields=['is_2fa_enabled', 'otp_secret'])

        return Response({
            "status": "success",
            "code": 200,
            "message": "2FA가 성공적으로 비활성화되었습니다.",
            "data": {},
            "meta": {"timestamp": timezone.now().isoformat()}
        }, status=status.HTTP_200_OK)

class MeViewSet(viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="사용자 정보 조회",
        description="로그인한 사용자의 프로필 정보와 보안 설정을 반환합니다.",
        responses={
            200: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="성공적으로 사용자 정보를 반환함",
                examples=[
                    OpenApiExample(
                        "성공적으로 사용자 정보를 반환함",
                        value={
                            "status": "success",
                            "code": 200,
                            "message": "사용자 정보를 성공적으로 반환했습니다.",
                            "data": {
                                "id": 1,
                                "username": "user@example.com",
                                "email": "user@example.com",
                                "is_2fa_enabled": True,
                                "last_login": "2024-10-01T10:00:00Z"
                            },
                            "meta": {"timestamp": "2024-12-11T08:42:59.754719+00:00"}
                        }
                    )
                ]
            ),
            401: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="인증되지 않은 사용자",
                examples=[
                    OpenApiExample(
                        "인증되지 않은 사용자",
                        value={
                            "status": "error",
                            "code": 401,
                            "message": "유효한 인증 정보가 제공되지 않았습니다.",
                            "error_code": "unauthorized",
                            "meta": {"timestamp": "2024-12-11T08:35:21.408328+00:00"}
                        }
                    )
                ]
            ),
        },
        tags=["Authentication"]
    )
    @action(detail=False, methods=['get'], url_path='@me')
    def profile(self, request):
        user = request.user
        return Response({
            "status": "success",
            "code": 200,
            "message": "사용자 정보를 성공적으로 반환했습니다.",
            "data": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "is_2fa_enabled": user.is_2fa_enabled,
                "last_login": user.last_login.isoformat() if user.last_login else None
            },
            "meta": {"timestamp": timezone.now().isoformat()}
        }, status=status.HTTP_200_OK)

class CustomTokenRefreshViewSet(viewsets.GenericViewSet):
    permission_classes = [AllowAny]
    serializer_class = TokenRefreshSerializer
    
    @extend_schema(
        summary="토큰 갱신",
        description="리프레시 토큰을 사용하여 새로운 액세스 토큰을 발급합니다.",
        request=TokenRefreshSerializer,
        responses={
            200: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="토큰 갱신 성공",
                examples=[
                    OpenApiExample(
                        "토큰 갱신 성공",
                        value={
                            "status": "success",
                            "code": 200,
                            "message": "토큰 갱신에 성공했습니다.",
                            "data": {"access": "new-access-token"},
                            "meta": {
                                "timestamp": "2025-01-07T12:00:00.000000+00:00",
                                "user_id": 1,
                                "username": "example_user",
                                "token_issued_at": 1709877600,
                                "token_expires_at": 1709881200
                            }
                        }
                    )
                ]
            ),
            400: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="잘못된 요청",
                examples=[
                    OpenApiExample(
                        "잘못된 요청",
                        value={
                            "status": "error",
                            "code": 400,
                            "message": "유효하지 않은 리프레시 토큰입니다.",
                            "error_code": "invalid_refresh_token",
                            "meta": {
                                "timestamp": "2025-01-07T12:00:00.000000+00:00"
                            }
                        }
                    )
                ]
            ),
            403: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="사용자 비활성화",
                examples=[
                    OpenApiExample(
                        "사용자 비활성화",
                        value={
                            "status": "error",
                            "code": 403,
                            "message": "이 사용자는 비활성화 상태입니다.",
                            "error_code": "user_inactive",
                            "meta": {
                                "timestamp": "2025-01-07T12:00:00.000000+00:00"
                            }
                        }
                    )
                ]
            ),
            500: OpenApiResponse(
                response=OpenApiTypes.OBJECT,
                description="서버 에러",
                examples=[
                    OpenApiExample(
                        "서버 에러",
                        value={
                            "status": "error",
                            "code": 500,
                            "message": "토큰 갱신 중 오류가 발생했습니다.",
                            "error_code": "server_error",
                            "meta": {
                                "timestamp": "2025-01-07T12:00:00.000000+00:00"
                            }
                        }
                    )
                ]
            ),
        },
        tags=["Authentication"]
    )
    @action(detail=False, methods=['post'], url_path='refresh')
    def token_refresh(self, request, *args, **kwargs):
        serializer = TokenRefreshSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "status": "error",
                "code": 400,
                "message": "요청 데이터가 유효하지 않습니다.",
                "error_code": "invalid_request",
                "errors": serializer.errors,
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_400_BAD_REQUEST)

        decoded_token = serializer.context['decoded_token']
        user = serializer.context['user']
        access_token = str(decoded_token.access_token)

        response = {
            "status": "success",
            "code": 200,
            "message": "토큰 갱신에 성공했습니다.",
            "data": {"access": access_token},
            "meta": {
                "timestamp": timezone.now().isoformat(),
                "user_id": user.id,
                "username": user.username,
                "token_issued_at": decoded_token.current_time,
                "token_expires_at": decoded_token.access_token['exp']
            }
        }
        return Response(response, status=status.HTTP_200_OK)

class PasswordResetViewSet(viewsets.GenericViewSet):
    permission_classes = [IsAuthenticated]
    serializer_class = PasswordResetRequestSerializer

    @extend_schema(
        summary="비밀번호 재설정 요청",
        description="사용자의 이메일로 비밀번호 재설정을 위한 링크를 전송합니다.",
        request=PasswordResetRequestSerializer,
        parameters=[
            OpenApiParameter(
                name="email",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="비밀번호 재설정을 요청할 이메일 주소입니다.",
                required=True,
                examples=[
                    OpenApiExample(
                        name="예시 이메일",
                        value="user@example.com",
                        description="사용자의 이메일 주소"
                    )
                ]
            ),
        ],
        responses={
            200: OpenApiResponse(
                description="비밀번호 재설정 이메일 전송 성공",
                examples=[
                    OpenApiExample(
                        name="성공 응답",
                        value={
                            "status": "success",
                            "message": "비밀번호 재설정 링크가 이메일로 전송되었습니다.",
                            "meta": {"timestamp": "2025-01-09T08:00:00+00:00"}
                        }
                    )
                ],
            ),
            400: OpenApiResponse(
                description="잘못된 요청 데이터",
                examples=[
                    OpenApiExample(
                        name="잘못된 이메일",
                        value={
                            "status": "error",
                            "message": "해당 이메일로 등록된 사용자가 없습니다.",
                            "meta": {"timestamp": "2025-01-09T08:00:00+00:00"}
                        }
                    ),
                    OpenApiExample(
                        name="비활성화 계정",
                        value={
                            "status": "error",
                            "message": "해당 계정은 비활성화 상태입니다.",
                            "meta": {"timestamp": "2025-01-09T08:00:00+00:00"}
                        }
                    ),
                ],
            ),
            500: OpenApiResponse(
                description="서버 에러",
                examples=[
                    OpenApiExample(
                        name="서버 에러",
                        value={
                            "status": "error",
                            "message": "비밀번호 재설정 요청 처리 중 문제가 발생했습니다.",
                            "meta": {"timestamp": "2025-01-09T08:00:00+00:00"}
                        }
                    )
                ],
            ),
        },
        tags=["Authentication"]
    )
    @action(detail=False, methods=["post"], url_path='request')
    def request1(self, request):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            email = serializer.validated_data["email"]
            user = User.objects.get(email=email)

            token = crypto.get_random_string(length=32)
            cache.set(f"password_reset_token_{token}", user.id, timeout=900)
            
            reset_link = f"{settings.BASE_URL}/password/reset/confirm/{token}"
            send_password_reset_email.delay(email, reset_link)

            return Response({
                "status": "success",
                "message": "비밀번호 재설정 링크가 이메일로 전송되었습니다.",
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_200_OK)

        except serializers.ValidationError as ve:
            logger.warning(f"비밀번호 재설정 요청 실패 (유효성 오류): {ve}")
            return Response({
                "status": "error",
                "message": str(ve),
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"비밀번호 재설정 요청 처리 중 서버 에러: {e}")
            return Response({
                "status": "error",
                "message": "비밀번호 재설정 요청 처리 중 문제가 발생했습니다.",
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @extend_schema(
        summary="비밀번호 재설정 확인",
        description="비밀번호 재설정을 위한 토큰과 새 비밀번호를 받아 검증 후 비밀번호를 변경합니다.",
        request=PasswordResetConfirmSerializer,
        responses={
            200: OpenApiResponse(
                description="비밀번호 재설정 성공",
                examples=[
                    OpenApiExample(
                        name="성공 응답",
                        value={
                            "status": "success",
                            "message": "비밀번호가 성공적으로 변경되었습니다.",
                            "meta": {"timestamp": "2025-01-09T08:00:00+00:00"}
                        }
                    )
                ],
            ),
            400: OpenApiResponse(
                description="유효하지 않은 토큰 또는 입력 오류",
                examples=[
                    OpenApiExample(
                        name="유효하지 않은 토큰",
                        value={
                            "status": "error",
                            "message": "유효하지 않거나 만료된 토큰입니다.",
                            "meta": {"timestamp": "2025-01-09T08:00:00+00:00"}
                        }
                    ),
                    OpenApiExample(
                        name="비밀번호 불일치",
                        value={
                            "status": "error",
                            "message": "비밀번호와 확인 비밀번호가 일치하지 않습니다.",
                            "meta": {"timestamp": "2025-01-09T08:00:00+00:00"}
                        }
                    ),
                ],
            ),
            500: OpenApiResponse(
                description="서버 에러",
                examples=[
                    OpenApiExample(
                        name="서버 에러",
                        value={
                            "status": "error",
                            "message": "비밀번호 재설정 처리 중 문제가 발생했습니다.",
                            "meta": {"timestamp": "2025-01-09T08:00:00+00:00"}
                        }
                    )
                ],
            ),
        },
        tags=["Authentication"]
    )
    @action(detail=False, methods=["post"], url_path="confirm")
    def confirm(self, request):
        try:
            serializer = PasswordResetConfirmSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            token = serializer.validated_data["token"]
            new_password = serializer.validated_data["new_password"]

            user_id = cache.get(f"password_reset_token_{token}")
            if not user_id:
                logger.warning(f"비밀번호 재설정 실패 - 유효하지 않은 토큰: {token}")
                return Response({
                    "status": "error",
                    "message": "유효하지 않거나 만료된 토큰입니다.",
                    "meta": {"timestamp": timezone.now().isoformat()}
                }, status=status.HTTP_400_BAD_REQUEST)

            user = User.objects.get(id=user_id)
            user.set_password(new_password)
            user.save()

            cache.delete(f"password_reset_token_{token}")

            logger.info(f"비밀번호 재설정 완료: {user.email}")

            return Response({
                "status": "success",
                "message": "비밀번호가 성공적으로 변경되었습니다.",
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_200_OK)

        except serializers.ValidationError as ve:
            logger.warning(f"비밀번호 재설정 확인 실패 (유효성 오류): {ve}")
            return Response({
                "status": "error",
                "message": str(ve),
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"비밀번호 재설정 확인 중 서버 에러: {e}")
            return Response({
                "status": "error",
                "message": "비밀번호 재설정 처리 중 문제가 발생했습니다.",
                "meta": {"timestamp": timezone.now().isoformat()}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
