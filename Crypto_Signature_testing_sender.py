from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256


#Generating the RSA keypair
#    param: bits The key length in bits
#    Writing the private key and public key to seperate files


bits =1024

new_key =RSA.generate(bits)
public_key = new_key.publickey().exportKey("PEM") 
private_key = new_key.exportKey("PEM") 
print "private_key: " + str( private_key)
print "public key: " + str(public_key)
f = open('cprkey.pem','w')
f.write(private_key)
f.close()

f = open('cpckey.pem','w')
f.write(public_key)
f.close()

f = open('cprkey.pem','r')
key = RSA.importKey(f.read())
print "private key: " + str(key.exportKey("PEM"))
f.close()

message = 'To be signed hjhkh'
h = SHA256.new(message)
signer = PKCS1_v1_5.new(key)
signature = signer.sign(h)

#signature = signature + 'screw'
trans_msg = signature+'DEADBEEF'+message

f = open('cpckey.pem','r')
key1 = RSA.importKey(f.read())
print "public key: " + str(key1.exportKey("PEM"))
f.close()

signature2,temp,message2 = trans_msg.partition('DEADBEEF')
h1= SHA256.new(message2)


verifier = PKCS1_v1_5.new(key1)
if verifier.verify(h1, signature):
    print "The signature is authentic."
else:
    print "The signature is not authentic."

print "hi guys"



