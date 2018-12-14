from ecdsa import SigningKey, NIST384p
from ecdsa.util import randrange_from_seed__trytryagain
from django.contrib.auth.models import User
from binascii import hexlify
from initial_data.generate_usernames import get_uname
from initial_data.random_words import gen_passphrase
import os, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import names
import random
import hashlib

from ecdsa import NIST384p, SigningKey
from ecdsa.util import randrange_from_seed__trytryagain

"""
To run this script, enter a django shell:
...
>>> exec(open("initial_data/generate_keys.py").read())
"""


def make_key(seed):
  secexp = randrange_from_seed__trytryagain(seed, NIST384p.order)
  return SigningKey.from_secret_exponent(secexp, curve=NIST384p)

def make_ecdsa_keys():
        seed = os.urandom(NIST384p.baselen) # or other starting point
        seed_hex = seed.hex()#.decode('ascii')
        sk = make_key(seed)
        vk = sk.get_verifying_key()
        sk_hex = hexlify(sk.to_string()).decode('ascii')
        vk_hex = hexlify(vk.to_string()).decode('ascii')
        print('pub: ' + vk_hex)
        print('key: ' + sk_hex)
        print('seed: ' + sk_hex)
        return (seed_hex, sk_hex, vk_hex)

def make_rsa_users():
    for i in range(35):
        key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=2048)
        public_key = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        pem = key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption())
        public_key = str(public_key,"utf-8")
        pem = str(pem,"utf-8")
        #print(pem)
        #print(public_key)
        #first,last = get_uname(0,255,False)
        first = names.get_first_name(gender=random.choice(["male","female"]))
        last = names.get_last_name()
        uname = first.lower() + random.choice([".","_"]) + last.lower()       
        mail = uname + "@" + "mail.com"
        user = User()
        user.username = uname
        print("create user: " + uname)
        user.first_name = first
        user.last_name = last
        user.email = mail
        passphrase = gen_passphrase() 
        print("passphrase: " + passphrase)
        user.set_password(passphrase)
        user.save()
        user.profile.passphrase = passphrase
        user.profile.passphrase_hash = hashlib.sha256(passphrase.encode()).hexdigest()
        user.profile.rsa_public_key = public_key
        user.profile.rsa_private_key = pem
        ecdsa_keys = make_ecdsa_keys()
        user.profile.ecdsa_public_key = ecdsa_keys[2]
        user.profile.ecdsa_private_key = ecdsa_keys[1]
        user.profile.seed = ecdsa_keys[0]
        user.save()
        #print(private_key_str)
        #print(public_key_str)

def delete_users():
    print('deleting all users except admin!')
    users = User.objects.all()
    for i in users:
        if i.username != "admin":
            print("deleting " + i.username)
            i.delete()
delete_users()
make_rsa_users()

