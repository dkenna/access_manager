import jwt
import python_jwt as jwt, jwcrypto.jwk as jwk, datetime
import time
from ecdsa import SigningKey, NIST384p
from ecdsa.util import randrange_from_seed__trytryagain
from django.contrib.auth.models import User
from binascii import hexlify
import os
import vault as VAULT

"""
To run this script, enter a django shell:
...
>>> exec(open("./tokenizer.py").read())
"""

def bitstring_to_bytes(s):
    return int(s, 2).to_bytes((len(s) + 7)// 8, byteorder='big')

class Challenge:
    def __init__(self):
        self.timestamp = int(time.time())

    def signed_timestamp(self):
        claim = {'timestamp':self.timestamp}
        token = jwt.encode(claim, VAULT.rsa_key, algorithm='RS256').decode('utf-8')
        return token

    def get_timestamp(self):
        return {'timestamp':self.timestamp}
        
rsa_users = ["AbleArticle","AbleHearing","AccurateInteraction"]

def test():
    challenge = Challenge()
    print(challenge.timestamp)
    timestamp = challenge.get_timestamp()
    users = User.objects.filter(username__in = rsa_users)
    for i in users:
        #print(i.profile.private_key)
        #b = bytearray(i.profile.private_key,encoding="utf-8")
        key = jwk.JWK.from_pem(i.profile.private_key)
        token = jwt.generate_jwt(timestamp, key, 'RS512', datetime.timedelta(minutes=5))
        #print(dir(key))
        #print(str(key.export_to_pem(private_key=True,password=None),"utf-8"))
        print(str(i.profile.public_key,"utf-8"))
        print(token)
    """
    token = challenge.signed_timestamp()
    print(token)
    payload = jwt.decode(token, VAULT.rsa_pub, algorithms=['RS256'])
    print(payload)
    """
test()


