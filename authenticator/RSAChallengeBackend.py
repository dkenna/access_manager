from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from tokenizer import AuthChallenge, ChallengeVerifier
from jwt.exceptions import InvalidSignatureError

class RSAChallengeBackend:
    """
       backed that works with signed challenges   
    """

    def authenticate(self, request, username, signed_challenge):
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return None
        try:
            verifier = ChallengeVerifier()
            pub_key = user.profile.public_key
            decoded = verifier.verify(pub_key,signed_challenge)
            print(f"user authenticated: {user.username}")
        except Exception as e:
            """log some shit here"""
            print("sig decoding. authentication failed.")
            print(type(e))
            print(e)
            return None
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
