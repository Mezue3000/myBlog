# import libraries
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
import os



# generate a Fernet key
key = os.getenv("SPIRIT_KEY").encode()
fernet = Fernet(key)



# load private key from file
with open("C:/Users/HP/Desktop/Python-Notes/myBlog/server/ec_private.pem", "rb") as f:
     PRIVATE_KEY = f.read()



# encrypt/save senstive data
ENCRYPTED_PRIVATE_KEY = fernet.encrypt(PRIVATE_KEY)
with open("C:/Users/HP/Desktop/Python-Notes/myBlog/server/ec_private.pem.enc", "wb") as f:
    f.write(ENCRYPTED_PRIVATE_KEY)  
    
    
