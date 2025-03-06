from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import CustomUser, LoginHistory, EmailVerification
from .exceptions import InvalidCredentialsException, AccountInactiveException
from django.core.cache import cache
from django.utils.translation import gettext_lazy as _
from django.core.validators import RegexValidator, MinLengthValidator
from datetime import timedelta
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken
import re
import pyotp
import logging

logger = logging.getLogger(__name__)

class CustomUserCreationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        help_text='비밀번호는 최소 8자 이상이어야 하며, 숫자와 특수문자를 포함해야 합니다.'
    )
    password2 = serializers.CharField(
        write_only=True,
        required=True,
        style={'input_type': 'password'},
        help_text='비밀번호 확인을 위해 다시 입력해주세요.'
    )
    email = serializers.EmailField(
        required=True,
        help_text='유효한 이메일 주소를 입력해주세요. 인증 코드가 이 주소로 전송됩니다.'
    )
    phone_number = serializers.CharField(
        required=True,
        help_text='유효한 전화번호를 입력해주세요. 예: 010-1234-5678'
    )

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password', 'password2', 'phone_number']

    def validate_username(self, value):
        if CustomUser.objects.filter(username=value).exists():
            raise serializers.ValidationError({"username": "이미 사용 중인 사용자 이름입니다."})
        if not re.match(r'^[\w.@+-]+$', value):
            raise serializers.ValidationError({"username": "사용자 이름은 문자, 숫자 및 @/./+/-/_만 포함할 수 있습니다."})
        return value

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError({"email": "이미 등록된 이메일 주소입니다."})
        return value

    def validate_phone_number(self, value):
        if not re.match(r'^\d{3}-\d{3,4}-\d{4}$', value):
            raise serializers.ValidationError({"phone_number": "올바른 전화번호 형식이 아닙니다. 예: 010-1234-5678"})
        if CustomUser.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError({"phone_number": "이미 등록된 전화번호입니다."})
        return value

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "비밀번호가 일치하지 않습니다."})

        try:
            validate_password(attrs['password'])
        except ValidationError as e:
            raise serializers.ValidationError({"password": list(e.messages)})

        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        user = CustomUser.objects.create_user(**validated_data)
        user.is_active = False
        user.save()
        return user

class CustomAuthTokenSerializer(serializers.Serializer):
    username = serializers.CharField(label=_("Username"), write_only=True)
    password = serializers.CharField(label=_("Password"), style={'input_type': 'password'}, trim_whitespace=False, write_only=True)

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        if username and password:
            user = authenticate(request=self.context.get('request'), username=username, password=password)

            if not user:
                raise InvalidCredentialsException()
            if not user.is_active:
                raise AccountInactiveException()
        else:
            raise serializers.ValidationError({
                "detail": _('Must include "username" and "password".')
            }, code='authorization')

        attrs['user'] = user
        return attrs

class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_new_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError({"new_password": "비밀번호는 최소 8자 이상이어야 합니다."})
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError({"new_password": "비밀번호는 최소 하나의 대문자를 포함해야 합니다."})
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError({"new_password": "비밀번호는 최소 하나의 소문자를 포함해야 합니다."})
        if not re.search(r'\d', value):
            raise serializers.ValidationError({"new_password": "비밀번호는 최소 하나의 숫자를 포함해야 합니다."})
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError({"new_password": "비밀번호는 최소 하나의 특수문자를 포함해야 합니다."})
        return value

    def validate(self, attrs):
        user = self.context['request'].user
        if not user.check_password(attrs['old_password']):
            raise serializers.ValidationError({"old_password": "현재 비밀번호가 올바르지 않습니다."})
        return attrs

    def save(self, **kwargs):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user

class CallbackUserInfoSerializer(serializers.Serializer):
    code = serializers.CharField(required=True, help_text="Google 인증 코드")

    def validate_code(self, value):
        if len(value) != 6 or not value.isdigit():
            raise serializers.ValidationError({"code": "유효한 인증 코드가 아닙니다."})
        return value

class StartEnable2FASerializer(serializers.Serializer):
    pass

class Enable2FASerializer(serializers.Serializer):
    user = serializers.HiddenField(default=serializers.CurrentUserDefault())
    otp_secret = serializers.CharField(read_only=True, help_text="2FA 활성화를 위한 OTP 시크릿 키")

    def save(self, **kwargs):
        user = self.validated_data['user']
        user.is_2fa_enabled = True
        user.otp_secret = pyotp.random_base32()
        user.save()
        return {"otp_secret": user.otp_secret}

class Verify2FASerializer(serializers.Serializer):
    token = serializers.CharField(
        required=True,
        max_length=6,
        help_text=_("2FA 인증 코드")
    )

    def validate(self, attrs):
        token = attrs.get('token')
        user = self.context['request'].user
        
        if not user:
            raise serializers.ValidationError({
                "user": _("존재하지 않는 사용자입니다."),
                "error_code": "user_not_found"
            })

        if not user.is_2fa_enabled:
            raise serializers.ValidationError({
                "2fa": _("2FA가 활성화되지 않았습니다."),
                "error_code": "2fa_not_enabled"
            })

        totp = pyotp.TOTP(user.otp_secret)
        if not totp.verify(token):
            raise serializers.ValidationError({
                "token": _("유효하지 않은 인증 코드입니다."),
                "error_code": "invalid_2fa_token"
            })

        return attrs

class Disable2FASerializer(serializers.Serializer):
    otp = serializers.CharField(
        required=True,
        max_length=6,
        help_text=_("사용자가 입력한 OTP")
    )

    def validate(self, attrs):
        otp = attrs.get('otp')
        user = self.context['request'].user

        if not user.is_2fa_enabled or not user.otp_secret:
            raise serializers.ValidationError("2FA가 활성화되어 있지 않습니다.")

        try:
            totp = pyotp.TOTP(user.otp_secret)
        except Exception:
            raise serializers.ValidationError("OTP 생성 중 오류가 발생했습니다.")
        if not totp.verify(otp):
            raise serializers.ValidationError("OTP가 유효하지 않습니다.")

        return attrs
 
class EmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField(
        help_text="인증받을 이메일",
        error_messages={
            'required': '이메일을 입력해주세요.',
            'invalid': '올바른 이메일 형식이 아닙니다.',
            'blank': '이메일을 입력해주세요.'
        }
    )
    
    verification_code = serializers.CharField(
        help_text="이메일로 받은 6자리 인증 코드",
        validators=[
            RegexValidator(
                regex=r'^\d{6}$',
                message='인증코드는 6자리 숫자여야 합니다.'
            ),
            MinLengthValidator(6)
        ],
        error_messages={
            'required': '인증코드를 입력해주세요.',
            'blank': '인증코드를 입력해주세요.'
        }
    )

    def validate_email(self, value):
        if not CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("등록되지 않은 이메일입니다.")
        return value

    def validate_verification_code(self, value):
        if len(value) != 6:
            raise serializers.ValidationError("인증코드는 6자리여야 합니다.")
        if not value.isdigit():
            raise serializers.ValidationError("인증코드는 숫자만 입력 가능합니다.")
        return value

    def validate(self, data):
        email = data.get('email')
        code = data.get('verification_code')
       
        try:
            verification = EmailVerification.objects.get(
                user__email=email,
                code=code,
                created_at__gte=timezone.now() - timedelta(minutes=30)
            )
           
            if verification.is_used:
                raise serializers.ValidationError({
                    "verification_code": "이미 사용된 인증코드입니다."
                })
                
            if verification.attempts >= 5:
                raise serializers.ValidationError({
                    "verification_code": "인증 시도 횟수를 초과했습니다. 새로운 인증코드를 발급받으세요."
                })
                
        except EmailVerification.DoesNotExist:
            raise serializers.ValidationError({
                "verification_code": "유효하지 않거나 만료된 인증코드입니다."
            })
            
        data['verification'] = verification
        return data

    class Meta:
        fields = ('email', 'verification_code')
        read_only_fields = ()
        
    def to_representation(self, instance):
        return {
            'email': instance.get('email'),
            'is_verified': True,
            'verified_at': timezone.now().isoformat()
        }

class TokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField(
        required=True,
        help_text="리프레시 토큰을 입력하세요.",
        error_messages={
            'blank': "리프레시 토큰이 비어 있습니다.",
            'required': "리프레시 토큰이 제공되지 않았습니다.",
        }
    )

    def validate_refresh(self, value):
        try:
            decoded_token = RefreshToken(value)
        except Exception:
            raise serializers.ValidationError("유효하지 않은 리프레시 토큰입니다.")

        user = CustomUser.objects.filter(id=decoded_token['user_id']).first()
        if not user or not user.is_active:
            raise serializers.ValidationError("이 사용자는 비활성화 상태입니다.")
        
        self.context['decoded_token'] = decoded_token
        self.context['user'] = user
        return value
    
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        try:
            user = CustomUser.objects.get(email=value)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("해당 이메일로 등록된 사용자가 없습니다.")
        if not user.is_active:
            raise serializers.ValidationError("해당 계정은 비활성화 상태입니다.")
        return value

class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=8, max_length=128)
    confirm_password = serializers.CharField(min_length=8, max_length=128)

    def validate_token(self, value):
        user_id = cache.get(f"password_reset_token_{value}")
        if not user_id:
            raise serializers.ValidationError("유효하지 않거나 만료된 토큰입니다.")
        return value

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError("비밀번호와 확인 비밀번호가 일치하지 않습니다.")
        return attrs
    
class CustomTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    def validate_refresh_token(self, value):
        try:
            token = RefreshToken(value)
            return token
        except Exception:
            raise serializers.ValidationError("유효하지 않은 리프레시 토큰입니다.")