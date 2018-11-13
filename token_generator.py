import jwt 
from jwt.algorithms import RSAAlgorithm
import time
from datetime import datetime
from django.contrib.auth.models import User
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os
import vault as VAULT
import random

"""
To run this script, enter a django shell:
...
>>> exec(open("./tokenizer.py").read())
"""

SIGNING_ALGO = "RS256"
TOKEN_TTL = 300 #5 minutes
TOKEN_TTL_LOGIN = 120 #22 minutes

class Token:
    _jit = random.randint(100000000,999999999)

    def __init__(self):
        self.claims = {}
        self.claims['exp'] = self.now() + TOKEN_TTL
        self.claims['nbf'] = self.now()
        self.claims['iss'] = "urn:auth_server"
        self.claims['aud'] = "urn:anybody"
        self.claims['iat'] = self.now()
        self.claims['jit'] = Token._jit 
        Token._jit += 1

    def signed(self):
        token = jwt.encode(self.claims, VAULT.rsa_key, algorithm=SIGNING_ALGO).decode('utf-8')
        return token

    def now(self):
        return int(time.time())
        
    def verify(self,pub):
        return jwt.decode(self.token, pub, algorithms=SIGNING_ALGO)

    def verify_timestamp(self):
        return self.token["exp"] > self.now()

class ChallengeToken(Token):
    """
        Token with a shortened expiration time,
        used for login.
    """
    def __init__(self):
        super().__init__()
        self.claims['exp'] = self.now() + TOKEN_TTL_LOGIN

class Challenge:
    def get_signed_timestamp(self):
        timestamp = int(time.time())
        claim = {'timestamp':timestamp}
        token = jwt.encode(claim, VAULT.rsa_key, algorithm=SIGNING_ALGO).decode('utf-8')
        return token

    def get_jwk(self):
        pub_bytes = bytes(VAULT.rsa_pub_pem,"utf-8")
        public_key = serialization.load_pem_public_key(pub_bytes, backend=default_backend())
        return RSAAlgorithm.to_jwk(public_key)

    def validate_timestamp(self,token):
        return jwt.decode(token, VAULT.rsa_pub_pem, algorithms=SIGNING_ALGO)

class SignedChallengeVerifier:

    def verify(self,username,signed_challenge):
        """
            check if signed_challenged is signed by the private
            key of username.
        """
        pub = User.objects.get(username=username).profile.public_key
        return jwt.decode(signed_challenge, pub, algorithms=SIGNING_ALGO)

    def verify_timestamp(self,timestamp):
        """
            chech if the timestamp is not older than 300 seconds
        """
        now = int(time.time())
        return (now - timestamp) < TOKEN_TTL_LOGIN

def test():
    for i in range(25):
        challenge = Challenge()
        token = challenge.signed_timestamp()
        print(token)
        key = challenge.get_jwk()
        print(key)
        time.sleep(1)

