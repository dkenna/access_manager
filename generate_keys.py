from ecdsa import SigningKey, NIST384p
from ecdsa.util import randrange_from_seed__trytryagain
from django.contrib.auth.models import User
from binascii import hexlify
from generate_usernames import get_uname
import os
#from django.core.management import setup_environ
#from access_manager import settings
#setup_environ(settings)

outfile = open('keys.txt','w')

def make_key(seed):
  secexp = randrange_from_seed__trytryagain(seed, NIST384p.order)
  return SigningKey.from_secret_exponent(secexp, curve=NIST384p)

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
