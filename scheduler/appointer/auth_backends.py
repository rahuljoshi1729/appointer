

from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
import hashlib

User = get_user_model()

class SaltedPasswordBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        try:
            user = User.objects.get(email=username)
        except User.DoesNotExist:
            return None

        # Extract the salt from the stored password hash
        stored_password_hash = user.password
        salt, hashed_password = stored_password_hash.split('$', 1)

        # Hash the provided password using the same salt
        password_hash = hashlib.sha256((salt + password).encode()).hexdigest()

        # Check if the hashed password matches the stored password hash
        if password_hash == hashed_password:
            return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
