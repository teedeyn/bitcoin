from ecpy.curves import Curve
import secrets
from ecpy.keys       import ECPrivateKey
from ecpy.ecdsa      import ECDSA
import hashlib
from ecpy.formatters import decode_sig

import sys,binascii


curve = Curve.get_curve('secp256k1')

G = curve.generator
order = curve.order
t=0
msg = 'B2B48890C4F6E72F449D57E9F3C4D2F23F6CD49CF9AAE847DB195FBBB93D07B51'
if (len(sys.argv)>1):
  msg=str(sys.argv[1])
if (len(sys.argv)>2):
  t=int(sys.argv[2])

msg=msg.encode()

if (t==1): 
	curve = Curve.get_curve('NIST-P192')
elif (t==2): 
	curve = Curve.get_curve('NIST-P224')
elif (t==3): 
	curve = Curve.get_curve('NIST-P256')
elif (t==4): 
	curve = Curve.get_curve('secp192k1')
elif (t==5): 
	curve = Curve.get_curve('secp160k1')
elif (t==6): 
	curve = Curve.get_curve('secp224k1') 
elif (t==7): 
	curve = Curve.get_curve('Brainpool-p256r1') 
elif (t==8): 
	curve = Curve.get_curve('Brainpool-p224r1') 
elif (t==9): 
	curve = Curve.get_curve('Brainpool-p192r1') 
elif (t==10): 
	curve = Curve.get_curve('Brainpool-p160r1')       
elif (t==11): 
	curve = Curve.get_curve('secp256r1') 


print (f"Name: {curve.name}, y^2=x^3+a*x+b (mod p) Type: {curve.type}, Size: {curve.size}, a={curve.a}, b={curve.b}, G={curve.generator}, field={curve.field}, order={curve.order}")


sk = ECPrivateKey(secrets.randbits(32*8), curve)
if (curve.size==192):
  sk = ECPrivateKey(secrets.randbits(24*8), curve)
elif (curve.size==224):
  sk = ECPrivateKey(secrets.randbits(28*8), curve)
elif (curve.size==160):
  sk = ECPrivateKey(secrets.randbits(20*8), curve)



pk = sk.get_public_key()

print("Message: ",msg)
print("\nPrivate key:", hex(sk.d))
print(f"Public key: ({hex(pk.W.x)},{hex(pk.W.y)}")

print ("\n---- Signed with ECDSA ----")

signer = ECDSA()
sig    = signer.sign(msg,sk)
rtn=signer.verify(msg,sig,pk)

print(f"Signature verification: {rtn}")
print("\nSignature:", binascii.hexlify(sig).decode())
r,s = decode_sig(sig, fmt='DER')
print (f"\n(r,s) = ({r},{s})")

print ("\n---- Signed with RFC 6979 ----")
signer = ECDSA()
sig = signer.sign_rfc6979(msg,sk,hashlib.sha256)
rtn=signer.verify(msg,sig,pk)
print(f"Signature verification: {rtn}")
print("\nSignature:", binascii.hexlify(sig).decode())
r,s = decode_sig(sig, fmt='DER')
print (f"\n(r,s) = ({r},{s})")

print ("\n---- Signed with random k ----")
signer = ECDSA()
k=secrets.randbits(32*8)
sig = signer.sign_k(msg,sk,k)
rtn=signer.verify(msg,sig,pk)
print(f"Signature verification: {rtn}")
print("\nSignature:", binascii.hexlify(sig).decode())
r,s = decode_sig(sig, fmt='DER')
print (f"\n(r,s) = ({r},{s})")

