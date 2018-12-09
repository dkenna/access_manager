from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from tokenizer import AuthChallenge, ChallengeVerifier
from jwt.exceptions import InvalidSignatureError
import hashlib
from login.models import Profile

class PassphraseBackend:

    def authenticate(self, request, passphrase):
        try:
            phash = hashlib.sha224(passphrase.encode()).hexdigest()
            user = Profile.objects.get(passphrase_hash=phash).user
        except User.DoesNotExist:
            return None
        try:
            assert(passphrase == user.profile.passphrase)
            return user
        except:
            """log some shit here"""
            print("sig decoding failed")
            print(type(e))
            print(e)
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
