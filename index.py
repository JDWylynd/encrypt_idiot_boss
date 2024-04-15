from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64, os

# Helper method to convert bytes to strings
def utf8(s: bytes):
    return str(s, 'utf-8')

# Load private key from external file
def load_private_key(file_name):
    with open(file_name, 'rb') as file:
        private_key_data = file.read()
        private_key = serialization.load_pem_private_key(private_key_data, password=None, backend=default_backend())
    return private_key

# Helper method to decrypt a message with a given key
def decrypt_message(msg, key):
    decrypted_msg = key.decrypt(
        base64.b64decode(msg), 
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_msg

# Load public key from external file
def load_public_key(file_name):
    with open(file_name, 'rb') as file:
        public_key_data = file.read()
        public_key = serialization.load_pem_public_key(public_key_data, backend=default_backend())
    return public_key

# Helper method to encrypt message
def encrypt_message(msg, key):
    encrypted_msg = base64.b64encode(key.encrypt(
        msg, 
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ))
    return encrypted_msg # Returns the bytes

def loop_all():
    for files in os.listdir("encrypt_idiot_boss/user_profiles"):
        private_key = load_private_key("encrypt_idiot_boss/old_private_key.pem")
        with open(f"encrypt_idiot_boss/user_profiles/{files}", "rb") as file:
            encrypted_file = file.read()
        decrypted_msg = decrypt_message(encrypted_file, private_key)
        public_key = load_public_key('encrypt_idiot_boss/new_public_key.pem')
        encrypted_msg = encrypt_message(decrypted_msg, public_key)
        print(f"Encrypted message:\n{encrypted_msg}\n\n")
        fname = os.fsdecode(files)
        with open(f"encrypt_idiot_boss/new_user_profiles/{fname}", "wb") as file:
            file.write(encrypted_msg)
def main():

    os.mkdir("encrypt_idiot_boss/new_user_profiles")
    #DECRYPTION
    # Load the private key
    private_key = load_private_key("encrypt_idiot_boss/old_private_key.pem")

    # Open the encrypted message from the external file
    with open("encrypt_idiot_boss/user_profiles/aaron_diaz.bin", "rb") as file:
        encrypted_file = file.read()

    # Decrypt the message with the private key
    decrypted_msg = decrypt_message(encrypted_file, private_key)

    # Obtain the value of the public key
    public_key = load_public_key('encrypt_idiot_boss/new_public_key.pem')

    # Encrypt your message
    encrypted_msg = encrypt_message(decrypted_msg, public_key)
    print(f"Encrypted message:\n{encrypted_msg}\n\n")

    # Write the encrypted message to a file
    name = "aaron_diazprac"
    with open(f"encrypt_idiot_boss/new_user_profiles/{name}.bin", "wb") as file:
        file.write(encrypted_msg)
    
    loop_all()

    #
    
        


if __name__ == "__main__":
    main()