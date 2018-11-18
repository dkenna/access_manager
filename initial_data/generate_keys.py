from ecdsa import SigningKey, NIST384p
from ecdsa.util import randrange_from_seed__trytryagain
from django.contrib.auth.models import User
from binascii import hexlify
from initial_data.generate_usernames import get_uname
import os, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

"""
To run this script, enter a django shell:
...
>>> exec(open("initial_data/generate_keys.py").read())
"""


def make_key(seed):
  secexp = randrange_from_seed__trytryagain(seed, NIST384p.order)
  return SigningKey.from_secret_exponent(secexp, curve=NIST384p)

def make_rsa_users():
    for i in range(25):
        key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=2048)
        public_key = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
        pem = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
        public_key = str(public_key,"utf-8")
        pem = str(pem,"utf-8")
        print(pem)
        print(public_key)
        first,last = get_uname(0,255,False)
        uname = first + last
        mail = uname + "@" + "mail.com"
        user = User()
        user.username = uname
        user.first_name = first
        user.last_name = last
        user.email = mail
        user.set_password("password1")
        user.save()
        user.profile.public_key = public_key
        user.profile.private_key = pem
        user.save()
        #print(private_key_str)
        #print(public_key_str)

def delete_users():
    users = User.objects.all()
    for i in users:
        if i.username != "admin": i.delete()
#delete_users()
make_rsa_users()

def make_ecdsa_users():
    for i in range(25):
        seed = os.urandom(NIST384p.baselen) # or other starting point
        sk = make_key(seed)
        vk = sk.get_verifying_key()
        sk_hex = hexlify(sk.to_string())
        vk_hex = hexlify(vk.to_string())
        uname = get_uname(0,255,False)
        mail = uname + "@" + "mail.com"
        user = User()
        user.username = uname
        user.email = mail
        user.password = "password1"
        user.save()
        user.profile.public_key = vk_hex
        user.profile.private_key = sk_hex
        user.save()
        print(uname)
        print(sk_hex)
        print(vk_hex)
