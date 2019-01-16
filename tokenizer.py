import jwt 
from jwt.algorithms import RSAAlgorithm
import time
from datetime import datetime
#from django.contrib.auth.models import User

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key

import os
import vault as VAULT
import random

"""
To run this script, enter a django shell:
...
>>> exec(open("./tokenizer.py").read())
"""

SIGNING_ALGO = "RS256"
ALLOWED_ALGOS = ['RS256']
TOKEN_TTL = 600 #seconds
TOKEN_TTL_LOGIN = 600 #seconds
TOKEN_TYPES = ({"authentication":"auth","update_pub_key":"udpk"})

class ServerKeys:
    def get_jwk(self):
        pub_bytes = bytes(VAULT.rsa_pub,"utf-8")
        public_key = serialization.load_pem_public_key(pub_bytes, backend=default_backend())
        print(public_key)
        print('-------')
        #return [public_key.encode('ascii')]
        return RSAAlgorithm.to_jwk(public_key)

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

    def verify_header(self,token):
        pass

    def verify(self,token):
        return jwt.decode(token, VAULT.rsa_pub, algorithms=SIGNING_ALGO,\
                 audience=['urn:anybody'])

    def verify_timestamp(self):
        return self.token["exp"] > self.now()

    def get_jwk(self):
        pub_bytes = bytes(VAULT.rsa_pub,"utf-8")
        public_key = serialization.load_pem_public_key(pub_bytes, backend=default_backend())
        return RSAAlgorithm.to_jwk(public_key)
        
class UserToken(BaseToken):
    def __init__(self,user):
        super().__init__()
        self.user = user
        self.claims['username'] = user.username
        self.claims['sub'] = user.username
        self.claims['aud'] = user.username
        self.claims['email'] = user.email
        self.claims['first_name'] = user.first_name
        self.claims['last_name'] = user.last_name
        self.claims['typ'] = TOKEN_TYPES["authentication"]

class UpdateToken(BaseToken): 
    """ token to update a user's private key """
    def __init__(self,user):
        super().__init__()
        self.user = user
        self.claims['username'] = user.username
        self.claims['aud'] = user.username
        self.claims['typ'] = TOKEN_TYPES["update_pub_key"]

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
        self.errmsg = ""

    """def get_claim(self, claim):
        try:
            claims = jwt.decode(self.token, verify=False)
        except:
            self.errmsg = f"not a valid jwt token!"
            return None
        try:
            return claims[claim]
        except:
            self.errmsg = f"failed getting claim {claim}!"
            return None"""

    def verify_header(self):
        h = jwt.get_unverified_header(this.token)
        try:
            assert(h['alg'] in ALLOWED_ALGOS)
            return True
        except Exception as e:
            print(type(e))
            print(e)
            self.errmsg = "header verification faildes"
            return None
        pass
        
    def verify(self, username):
        """ check if signed by auth server for audience = username"""
        try: 
            return jwt.decode(self.token, VAULT.rsa_pub, algorithms=SIGNING_ALGO,\
                audience=[username])
        except Exception as e:
            print(type(e))
            print(e)
            self.errmsg = "failed sig verification"
            return None

class PemValidator:
    def validate(self, pub_key):
        try:
            print(pub_key)
            bpub_key = pub_key.encode() #expecting bytes
            serialization.load_pem_public_key(bpub_key, default_backend())
            return True
        except Exception as e:
            print(type(e))
            print(e)
            self.errmsg = "pub key validation failed"
            return False
        
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
