from django.contrib import admin
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.utils.timezone import now
from django.db.models import Count
from .models import CustomUser, LoginHistory, EmailVerification

def log_admin_action(user, action, message):
    """관리자 액션 로그 기록"""
    with open("admin_actions.log", "a", encoding="utf8") as f:
        f.write(f"[{now()}] {action} by {user}: {message}\n")


def send_email(user, subject, message):
    """유저에게 이메일을 전송하는 유틸리티 함수"""
    from django.core.mail import send_mail
    send_mail(
        subject,
        message,
        settings.EMAIL_HOST_USER,
        [user.email],
        fail_silently=False,
    )

class LoginHistoryInline(admin.TabularInline):
    model = LoginHistory
    extra = 0
    readonly_fields = ('login_time', 'ip_address', 'user_agent', 'success', 'location')
    can_delete = False
    verbose_name = _('로그인 기록')
    verbose_name_plural = _('로그인 기록들')

class CustomUserAdmin(admin.ModelAdmin):
    model = CustomUser

    list_display = (
        'username', 'email', 'phone_number', 'is_active', 
        'last_login', 'is_2fa_enabled'
    )
    list_filter = ('is_active', 'is_staff', 'date_joined', 'is_2fa_enabled')
    search_fields = ('username', 'email', 'phone_number')
    ordering = ('-date_joined',)
    readonly_fields = ('id', 'last_login', 'date_joined')

    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        (_('개인 정보'), {
            'fields': (
                'id', 'email', 'phone_number', 'first_name', 'last_name',
            )
        }),
        (_('계정 보안'), {'fields': ('is_2fa_enabled', 'otp_secret')}),
        (_('중요 날짜'), {'fields': ('last_login', 'date_joined')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'username', 'email', 'phone_number', 'password1', 'password2',
            ),
        }),
    )

    inlines = [LoginHistoryInline]

class LoginHistoryAdmin(admin.ModelAdmin):
    model = LoginHistory

    list_display = ('user', 'login_time', 'ip_address', 'user_agent', 'success', 'location', 'formatted_location')
    list_filter = ('success', 'login_time')
    search_fields = ('user__username', 'ip_address', 'user_agent', 'location')
    ordering = ('-login_time',)
    readonly_fields = ('user', 'login_time', 'ip_address', 'user_agent', 'success', 'location')

    def formatted_location(self, obj):
        return format_html('<span style="color: blue;">{}</span>', obj.location or _('Unknown'))
    formatted_location.short_description = _('Formatted Location')

    def changelist_view(self, request, extra_context=None):
        extra_context = extra_context or {}
        stats = self.model.objects.values('success').annotate(count=Count('id'))
        extra_context['stats'] = stats
        return super().changelist_view(request, extra_context=extra_context)

class EmailVerificationAdmin(admin.ModelAdmin):
    model = EmailVerification

    list_display = ('user', 'code', 'created_at', 'is_verified')
    list_filter = ('created_at', 'is_verified')
    search_fields = ('user__username', 'user__email', 'code')
    ordering = ('-created_at',)
    readonly_fields = ('user', 'code', 'created_at')

    @admin.action(description=_('선택된 이메일을 인증 완료로 표시'))
    def mark_as_verified(self, request, queryset):
        queryset.update(is_verified=True)
        log_admin_action(request.user, "mark_as_verified", f"Marked emails as verified: {', '.join([str(email) for email in queryset])}")
        self.message_user(request, _('선택된 이메일이 인증 완료로 표시되었습니다.'))

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(LoginHistory, LoginHistoryAdmin)
admin.site.register(EmailVerification, EmailVerificationAdmin)
