from binascii import hexlify, unhexlify
import sys
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

'''from ecdsa import SigningKey, NIST384p
from ecdsa.util import randrange_from_seed__trytryagain
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
private_key = ec.generate_private_key( ec.SECP384R1(), default_backend()  )
print(dir(private_key))
print(private_key.private_numbers().public_numbers)
'''
'''
seed = b'50db965ca9a96ac58dc757f9f79f8135c323080f105eb1f43c05ea38b9b90cde232bd7c938e960f90974fb42f981e458'
secexp = randrange_from_seed__trytryagain(unhexlify(seed), NIST384p.order)
ecdsa_key = SigningKey.from_secret_exponent(secexp, curve=NIST384p)
ecdsa_pub = ecdsa_key.get_verifying_key()
'''
rsa_key = open('keys/private_key').read()

rsa_pub = open('keys/public_key').read()

def decode_rsa(ciphertext):
    key = RSA.importKey(rsa_key)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    unhex = unhexlify(ciphertext)
    decoded = cipher.decrypt(unhexlify(ciphertext))
    hexmsg = hexlify(decoded).decode('ascii')
    print(hexmsg)
    return hexmsg 

class KeyGenerator:
    def make_key(seed):
        secexp = randrange_from_seed__trytryagain(seed, NIST384p.order)
        key = SigningKey.from_secret_exponent(secexp, curve=NIST384p)
        pub = key.get_verifying_key()
        return (key,pub)
