from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import RegexValidator
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.hashers import make_password, check_password
from utils.Snowflake import SnowflakeGenerator
from django.utils.functional import cached_property
from django.utils import timezone

snowflake_generator = SnowflakeGenerator(worker_id=1,epoch=1609459200000)

def generate_unique_id():
    return snowflake_generator.get_id(12)

USER_ROLES = (
    ('admin', '관리자'),
    ('user', '일반 사용자'),
)

class CustomUser(AbstractUser):
    id = models.BigIntegerField(
        primary_key=True,
        unique=True,
        editable=False,
        default=generate_unique_id 
    )
    email = models.EmailField(_('email address'), unique=True, db_index=True)
    phone_number = models.CharField(
        max_length=17,
        validators=[
            RegexValidator(
                regex=r'^\+?1?\d{9,15}$',
                message=_("전화번호는 9자에서 15자의 숫자만 포함할 수 있습니다.")
            )
        ],
        blank=True,
        null=True,
        db_index=True
    )
    is_2fa_enabled = models.BooleanField(default=False)
    otp_secret = models.CharField(max_length=128, blank=True, null=True)
    profile_image = models.ImageField(
        upload_to='profile_images/',
        default='defaultprofile.png',
        blank=True
    )
    role = models.CharField(
        max_length=20,
        choices=USER_ROLES,
        default='user'
    )
    score = models.IntegerField(default=0)
    rank = models.PositiveIntegerField(null=True, blank=True)
    social_account_type = models.CharField(
        max_length=20,
        choices=(('google', 'Google'), ('github', 'GitHub')),
        null=True,
        blank=True
    )
    social_id = models.CharField(max_length=100, null=True, blank=True)
    bio = models.TextField(blank=True, null=True)
    display_name = models.CharField(max_length=50, blank=True, null=True)
    language_preference = models.CharField(
        max_length=10,
        choices=[('en', 'English'), ('ko', 'Korean')],
        default='ko'
    )

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

    @cached_property
    def login_history(self, limit=10):
        return self.login_histories.only("login_time", "ip_address").order_by("-login_time")[:limit]

    def __str__(self):
        return self.username

    class Meta:
        indexes = [
            models.Index(fields=["id"]),
            models.Index(fields=["email"]),
        ]

class LoginHistory(models.Model):
    user = models.ForeignKey(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='login_histories'
    )
    location = models.CharField(max_length=255, blank=True, null=True)
    login_time = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    user_agent = models.TextField(blank=True)
    success = models.BooleanField(default=True)

    class Meta:
        ordering = ['-login_time']
        indexes = [
            models.Index(fields=['user', 'success', 'login_time']),
        ]
        verbose_name = _('로그인 기록')
        verbose_name_plural = _('로그인 기록들')

    def __str__(self):
        return f"{self.user.username} - {self.login_time}"

class EmailVerification(models.Model):
    user = models.OneToOneField(
        CustomUser,
        on_delete=models.CASCADE,
        related_name='email_verification',
        db_index=True
    )
    code = models.CharField(max_length=6, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False, db_index=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=["code"]),
            models.Index(fields=["is_verified"]),
        ]
        verbose_name = _('이메일 인증')
        verbose_name_plural = _('이메일 인증들')

    def __str__(self):
        return f"Verification for {self.user.username}"
