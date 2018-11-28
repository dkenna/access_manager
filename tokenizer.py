import jwt 
from jwt.algorithms import RSAAlgorithm
import time
from datetime import datetime
#from django.contrib.auth.models import User
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
TOKEN_TYPES = ({"authentication":"auth","update_pub_key":"udpk"})

class BaseToken:
    _jit = random.randint(100000000,999999999)
    def __init__(self):
        self.claims = {}
        self.claims['exp'] = self.now() + TOKEN_TTL
        self.claims['nbf'] = self.now()
        self.claims['iss'] = "urn:authn_server"
        self.claims['aud'] = "urn:anybody"
        self.claims['iat'] = self.now()
        self.claims['jit'] = BaseToken._jit        
        BaseToken._jit += 1

    def token(self):
        token = jwt.encode(self.claims, VAULT.rsa_key, algorithm=SIGNING_ALGO).decode('utf-8')
        return token

    def now(self):
        return int(time.time())
        
    def verify(self,token):
        return jwt.decode(token, VAULT.rsa_pub_pem, algorithms=SIGNING_ALGO,\
                 audience=['urn:anybody'])

    def verify_timestamp(self):
        return self.token["exp"] > self.now()

    def get_jwk(self):
        pub_bytes = bytes(VAULT.rsa_pub_pem,"utf-8")
        public_key = serialization.load_pem_public_key(pub_bytes, backend=default_backend())
        return RSAAlgorithm.to_jwk(public_key)
        
class UserToken(BaseToken):
    def __init__(self,user):
        super().__init__()
        self.user = user
        self.claims['username'] = user.username
        self.claims['email'] = user.email
        self.claims['first_name'] = user.first_name
        self.claims['last_name'] = user.last_name

class UpdateToken(BaseToken): 
    """ token to update a user's private key """
    def __init__(self,user):
        super().__init__(user)
        self.user = user
        self.claims['username'] = user.username

class AuthChallenge(BaseToken):
    '''
        token for auth
    '''
    def __init__(self):
        super().__init__()
        self.claims['exp'] = self.now() + TOKEN_TTL_LOGIN
        self.claims['typ'] = TOKEN_TYPES["authentication"]

class PubKeyChallenge(BaseToken):
    '''
        token for pub key update
    '''
    def __init__(self):
        super().__init__()
        self.claims['exp'] = self.now() + TOKEN_TTL_LOGIN
        self.claims['typ'] = TOKEN_TYPES["update_pub_key"]

class TokenVerifier:
    """
        verify self-emitted token
    """
    def __init__(self, token):
        self.token = token
    def verify(self):
        """ check if signed by user """
        return jwt.decode(self.token, VAULT.pub_key, algorithms=SIGNING_ALGO)

class ChallengeVerifier:
    """
        signed challenge (auth or key)
    """
    def verify(self,pub_key,signed_challenge):
        """ check if signed by user """
        return jwt.decode(signed_challenge, pub_key, algorithms=SIGNING_ALGO)

    def verify_timestamp(self,timestamp):
        """ check if timestamp < TOKEN_TTL_LOGIN """
        now = int(time.time())
        return (now - timestamp) < TOKEN_TTL_LOGIN


def test_tokens():
    for i in range(25):
        challenge = AuthChallenge()
        token = challenge.token()
        verify = challenge.verify(token)
        print(token)
        print(verify)
        key = challenge.get_jwk()
        print(key)
    for i in range(25):
        challenge = KeyChallenge()
        token = challenge.token()
        verify = challenge.verify(token)
        print(token)
        print(verify)
        key = challenge.get_jwk()
        print(key)

if __name__ == '__main__':
    test()
