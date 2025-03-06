from rest_framework.exceptions import APIException
from rest_framework import status

class AccountLockedException(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = '계정이 잠겼습니다. 관리자에게 문의하세요.'
    default_code = 'account_locked'

class InvalidCredentialsException(APIException):
    status_code = status.HTTP_401_UNAUTHORIZED
    default_detail = '아이디 또는 비밀번호가 잘못되었습니다.'
    default_code = 'invalid_credentials'

class AccountInactiveException(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = '계정이 비활성화되었습니다. 이메일을 확인해 주세요.'
    default_code = 'account_inactive'

class TooManyAttemptsException(APIException):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    default_detail = '로그인 시도가 너무 많습니다. 잠시 후 다시 시도해주세요.'
    default_code = 'too_many_attempts'
    
class MissingFieldException(APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = '필수 필드가 누락되었습니다. 필드를 확인하고 다시 시도하세요.'
    default_code = 'missing_field'
    
class GoogleAPIError(Exception):
    """Exception raised for errors in the Google API."""
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)

class UserCreationError(Exception):
    """Exception raised for errors during user creation."""
    def __init__(self, message):
        self.message = message
        super().__init__(self.message)