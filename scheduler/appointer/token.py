from django.contrib.auth.tokens import PasswordResetTokenGenerator
import datetime
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model


class CustomTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            str(user.pk) + str(timestamp) +
            str(user.is_active)
        )
    
    def get_token(self, user):
        timestamp = int(datetime.datetime.now().timestamp())
        uidb64 = urlsafe_base64_encode(str(user.pk).encode())
        return f'{uidb64}-{timestamp}'

    def get_user_from_token(self, token):
        try:
            uidb64, token = token.split('-')
            uid = urlsafe_base64_decode(uidb64).decode()
            return get_user_model().objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            return None

    def check_token(self, user, token):
        if not token:
            return False

        # Split the token to extract timestamp and token
        try:
            timestamp, token = token.split("-")
        except ValueError:
            return False

        try:
            timestamp = int(timestamp)
        except (TypeError, ValueError):
            return False

        # Check if the token has expired (1 minute lifetime)
        token_lifetime = datetime.timedelta(minutes=1)
        if timestamp + token_lifetime.total_seconds() < datetime.datetime.now().timestamp():
            return False

        return self._check_token(user, token)

custom_token_generator = CustomTokenGenerator()
