from django.urls import path, include
from rest_framework.routers import SimpleRouter
from .views import (
    SignupViewSet,
    VerifyEmailViewSet,
    LoginViewSet,
    GoogleLoginViewSet,
    GoogleCallbackViewSet,
    GitHubLoginViewSet,
    GitHubCallbackViewSet,
    StartEnable2FAViewSet,
    VerifyEnable2FAViewSet,
    Verify2FAViewSet,
    Disable2FAViewSet,
    MeViewSet,
    CustomTokenRefreshViewSet,
    PasswordResetViewSet
)

users_router = SimpleRouter()
users_router.register('', MeViewSet, basename='me')
users_router.register('@me/password/reset', PasswordResetViewSet, basename='password-reset')
users_router.register('@me/mfa/totp/enable', VerifyEnable2FAViewSet, basename='verify-enable-2fa')
users_router.register('@me/mfa/totp', StartEnable2FAViewSet, basename='enable-2fa')
users_router.register('@me/mfa/totp', Verify2FAViewSet, basename='2fa-verify')
users_router.register('@me/mfa/totp', Disable2FAViewSet, basename='2fa-disable')

auth_router = SimpleRouter()
auth_router.register('', LoginViewSet, basename='login')
auth_router.register('', SignupViewSet, basename='signup')
auth_router.register('signup', VerifyEmailViewSet, basename='verify-email')
auth_router.register('oauth/google', GoogleLoginViewSet, basename='google-login')
auth_router.register('oauth/google', GoogleCallbackViewSet, basename='google-callback')
auth_router.register('oauth/github', GitHubLoginViewSet, basename='github-login')
auth_router.register('oauth/github', GitHubCallbackViewSet, basename='github-callback')
auth_router.register('token', CustomTokenRefreshViewSet, basename='token-refresh')

urlpatterns = [
    path('users/', include(users_router.urls)),
    path('auth/', include(auth_router.urls)),
]
