import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Dummy data for demonstration purposes
sender_data = b"This is a secret message to be sent!"
receiver_address = ('127.0.0.1', 12345)

# Password for key derivation function (KDF) - should be kept secure
password = b"my_super_secret_password"


def generate_key(password: bytes) -> bytes:
    salt = b'dummy_salt_for_demo_only'  # In a real app, use a secure random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)


def encrypt_data(data: bytes, key: bytes) -> bytes:
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(data)


def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_data)


if __name__ == "__main__":
    try:
        # Step 1: Generate key from password
        key = generate_key(password)

        # Step 2: Encrypt the data
        encrypted_data = encrypt_data(sender_data, key)

        # Step 3: Send the encrypted data over the network
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(receiver_address)
            print(f"Sending encrypted data to {receiver_address}")
            sock.sendall(encrypted_data)

            # Step 4: Receive response (encrypted) and decrypt
            print("Waiting for response...")
            response = sock.recv(1024)
            decrypted_response = decrypt_data(response, key)

            print(f"Received decrypted response: {decrypted_response.decode()}")

    except Exception as e:
        print(f"An error occurred: {e}")
