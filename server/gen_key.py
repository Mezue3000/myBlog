# import dependencies
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization



# generate EC private key
private_key = ec.generate_private_key(ec.SECP256R1())



# serialize private key to pem
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)



# Save private key to files
with open("ec_private.pem", "wb") as f:
     f.write(private_pem)
     
     

# load private key from file
with open("ec_private.pem", "rb") as f:
     PRIVATE_KEY = f.read()

private_key = serialization.load_pem_private_key(PRIVATE_KEY, password=None)

     
     
# generate public key
public_key = private_key.public_key()



# Serialize public key to pem
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)



# Save public key to files
with open("ec_public.pem", "wb") as f:
     f.write(public_pem)