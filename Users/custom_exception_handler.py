from rest_framework.views import exception_handler
from django.http import JsonResponse
from django.utils.timezone import now
from .exceptions import (
    AccountLockedException,
    InvalidCredentialsException,
    AccountInactiveException,
    TooManyAttemptsException
)

def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if isinstance(exc, (AccountLockedException, InvalidCredentialsException, AccountInactiveException, TooManyAttemptsException)):
        return JsonResponse({
            "status": "error",
            "code": exc.status_code,
            "message": exc.default_detail,
            "error_code": exc.default_code,
            "meta": {
                "timestamp": now().isoformat()
            }
        }, status=exc.status_code)

    if response is not None:
        response.data = {
            "status": "error",
            "code": response.status_code,
            "message": response.data.get('detail', 'An error occurred'),
            "meta": {
                "timestamp": now().isoformat()
            }
        }

    return response
