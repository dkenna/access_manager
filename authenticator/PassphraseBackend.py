from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from tokenizer import AuthChallenge, SignedChallenge
from jwt.exceptions import InvalidSignatureError

class PassphraseBackend:
    """
    
    """

    def authenticate(self, request, username, passphrase):
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return None
        try:
            passphrase == user.profile.passphrase
        except Exception as e:
            """log some shit here"""
            print("sig decoding failed")
            print(type(e))
            print(e)
            return None
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
