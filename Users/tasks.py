from django.contrib.gis.geoip2 import GeoIP2
import requests
from celery import shared_task
from celery.utils.log import get_task_logger
from django.core.cache import cache
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from .models import LoginHistory, CustomUser

logger = get_task_logger(__name__)

@shared_task(bind=True, max_retries=3)
def get_location_from_ip(self, ip):
    cache_key = f"ip_location:{ip}"
    cached_location = cache.get(cache_key)
    if cached_location:
        return cached_location

    try:
        location = fetch_ip_location(ip)
        if location:
            cache.set(cache_key, location, timeout=3600)
            return location
        return "Unknown Location"
    except Exception as exc:
        logger.exception("IP 위치 조회 실패: %s", exc)
        raise self.retry(exc=exc, countdown=min(30 * (2 ** self.request.retries), 300))

def fetch_ip_location(ip):
    try:
        g = GeoIP2()
        location_data = g.city(ip)
        city = location_data.get("city")
        country = location_data.get("country_name")
        if city and country:
            location = f"{city}, {country}"
            return location
    except Exception as geoip_exc:
        logger.exception("GeoIP2 조회 실패: %s", geoip_exc)
    return None

@shared_task(bind=True, max_retries=5)
def send_verification_email(self, email, verification_code):
    try:
        send_email(
            subject='[Your Service] 이메일 인증을 완료해주세요.',
            to_email=email,
            template_name='verification_email.html',
            context={'verification_code': verification_code},
        )
        logger.info("Verification email sent to %s", email)
    except Exception as exc:
        logger.exception("Failed to send verification email to %s", email)
        raise self.retry(exc=exc, countdown=min(60 * (2 ** self.request.retries), 3600))

def send_email(subject, to_email, template_name, context):
    try:
        html_content = render_to_string(template_name, context)
        text_content = strip_tags(html_content)
        email = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[to_email],
        )
        email.attach_alternative(html_content, "text/html")
        email.send()
        logger.warning("Email sent to %s with subject '%s'", to_email, subject)
    except Exception as exc:
        logger.exception("Failed to send email to %s", to_email)
        raise

@shared_task(bind=True, max_retries=3)
def LoginHistoryTask(self, user_id, ip, user_agent, success, location):
    try:
        user = CustomUser.objects.get(id=user_id)
        LoginHistory.objects.create(
                    user=user,
                    ip_address=ip,
                    user_agent=user_agent,
                    success=success,
                    location=location or "Unknown Location"
            )
    except Exception as exc:
        logger.exception("Login History failed")
        raise self.retry(exc=exc, countdown=min(30 * (2 ** self.request.retries), 300))
    
@shared_task(bind=True, max_retries=3)
def send_password_reset_email(self, email, reset_link):
    """
    비밀번호 재설정 이메일 전송
    :param email: 수신자 이메일 주소
    :param reset_link: 비밀번호 재설정 링크
    """
    try:
        send_email(
            subject='비밀번호 재설정 요청',
            to_email=email,
            template_name='password_reset_email.html',
            context={
                'reset_link': reset_link
            },
        )
        logger.info("Password reset email sent to %s", email)
    except Exception as exc:
        logger.exception("Failed to send password reset email to %s", email)
        raise self.retry(exc=exc, countdown=min(60 * (2 ** self.request.retries), 3600))
