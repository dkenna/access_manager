import jwt 
from jwt.algorithms import RSAAlgorithm
import time
#from ecdsa import SigningKey, NIST384p
#from ecdsa.util import randrange_from_seed__trytryagain
#from binascii import hexlify
from django.contrib.auth.models import User
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os
import vault as VAULT

"""
To run this script, enter a django shell:
...
>>> exec(open("./tokenizer.py").read())
"""

class Challenge:
    def __init__(self):
        self.timestamp = int(time.time())

    def signed_timestamp(self):
        claim = {'timestamp':self.timestamp}
        token = jwt.encode(claim, VAULT.rsa_key, algorithm='RS512').decode('utf-8')
        return token

    def get_jwk(self):
        pub_bytes = bytes(VAULT.rsa_pub_pem,"utf-8")
        public_key = serialization.load_pem_public_key(pub_bytes, backend=default_backend())
        return RSAAlgorithm.to_jwk(public_key)

    def get_timestamp(self):
        return {'timestamp':self.timestamp}
        
def test():
    for i in range(25):
        challenge = Challenge()
        token = challenge.signed_timestamp()
        print(token)
        key = challenge.get_jwk()
        print(key)
        time.sleep(1)
test()


