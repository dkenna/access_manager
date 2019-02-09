from django.conf import settings
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import User
from tokenizer import AuthChallenge, ChallengeVerifier
from jwt.exceptions import InvalidSignatureError
import hashlib
from login.models import Profile
import logging
logger = logging.getLogger("django")

def log(msg):
    logger.debug(msg)
def log_error(e, msg):
    log(str(type(e)))
    log(str(e))
    log(msg)

class PassphraseBackend:

    def authenticate(self, request, username=None, passphrase=None):
        try:
            log(passphrase)
            user = Profile.objects.get(passphrase_hash=passphrase).user
        except Profile.DoesNotExist:
            return None
        try:
            assert(passphrase == user.profile.passphrase_hash)
            return user
        except Exception as e:
            log_error(e, "sig decoding. authentication failed.")
            return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
