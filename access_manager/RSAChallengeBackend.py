from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from token_generator import Challenge, SignedChallengeVerifier
from jwt.exceptions import InvalidSignatureError

class RSAChallengeBackend:
    """
    
    """

    def authenticate(self, request, username, signed_challenge):
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return None
        try:
            verifier = SignedChallengeVerifier()
            decoded = verifier.verify(username,signed_challenge)
        except Exception as e:
            """log some shit here"""
            print("sig decoding failed")
            print(e)
            return None
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
