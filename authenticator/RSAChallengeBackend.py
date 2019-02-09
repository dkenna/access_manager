from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from tokenizer import AuthChallenge, ChallengeVerifier
from jwt.exceptions import InvalidSignatureError
import logging
logger = logging.getLogger("django")

def log_error(e, msg):
    log(str(type(e)))
    log(str(e))
    log(msg)

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
            log_error(e, "sig decoding. authentication failed.")
            return None
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
