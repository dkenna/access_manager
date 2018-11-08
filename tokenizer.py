import jwt
import time
from ecdsa import SigningKey, NIST384p
from ecdsa.util import randrange_from_seed__trytryagain
from binascii import hexlify
import os
import vault as VAULT


class Challenge:
    def __init__(self):
        self.timestamp = time.time()

    def signed_timestamp(self):
        claim = {'timestamp':self.timestamp}
        token = jwt.encode(claim, VAULT.rsa_key, algorithm='RS256').decode('utf-8')
        return token
        

if __name__ == "__main__":
    for i in range(5):
        challenge = Challenge()
        print(challenge.timestamp)
        token = challenge.signed_timestamp()
        print(token)
        payload = jwt.decode(token, VAULT.rsa_pub, algorithms=['RS256'])
        print(payload)
        
        time.sleep(1)


