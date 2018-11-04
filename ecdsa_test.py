from ecdsa import SigningKey
sk = SigningKey.generate() # uses NIST192p
vk = sk.get_verifying_key()
signature = sk.sign("message".encode("utf-8"))
print(sk.to_pem())
s = sk.to_string().hex()
print(s)
print(s.encode("base64"))
#print(str(signature))
assert vk.verify(signature, "message".encode("utf-8"))
