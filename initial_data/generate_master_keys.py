from ecdsa import SigningKey, NIST384p
from ecdsa.util import randrange_from_seed__trytryagain
from binascii import hexlify
import os, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import names
import random
import hashlib


key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=2048)
public_key = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
private_key = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
public_key = str(public_key,"utf-8")
private_key = str(private_key,"utf-8")
open('keys/public_key','w').write(public_key)
open('keys/private_key','w').write(private_key)
