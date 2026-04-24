import argparse
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key

def readfile(filename: str) -> bytes:
    """
    Read file in binary mode
    """
    try:
        with open(filename, 'rb') as file:
            return file.read()
    except FileNotFoundError as e:
        return b""


def symmetric_key_generation()->bytes:
    """
    Generate symmetric keys
    """
    key = os.urandom(32)
    return key


def asymmetric_keys_generation():
    """
    Generate asymmetric keys
    """
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()

    return private_key, public_key


def secret_key_writter(secret_pem: str, private_key: bytes):
    """
    Write secret key
    """
    with open(secret_pem, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
              format=serialization.PrivateFormat.TraditionalOpenSSL,
              encryption_algorithm=serialization.NoEncryption()))


def public_key_writter(public_pem: str, public_key: bytes):
    """
    Write public key
    """
    with open(public_pem, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
             format=serialization.PublicFormat.SubjectPublicKeyInfo))


def asymmetric_keys_writter(secret_pem: str, public_pem: str, asymmetric_keys: tuple):
    """
    Write asymmetric keys
    """
    secret_key_writter(secret_pem, asymmetric_keys[0])
    public_key_writter(public_pem, asymmetric_keys[1])


def key_encription(symmetric_key: bytes, public_key: bytes, private_key_file: str):
    """
    Symmetric key encryption
    """
    try:
        return public_key.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    except ValueError:
        symmetric_key = symmetric_key_generation()
        return public_key.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))


def symmetric_key_writter(filepath: str, symmetric_key: bytes):
    """
    Write symmetric key
    """
    with open(filepath, "wb") as file:
        file.write(symmetric_key)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-sy", "--symmetric_key", required=True, help="Path to symmetric key file")
    parser.add_argument("-s", "--secret_key", required=True, help="Path to secret key file")
    parser.add_argument("-p", "--public_key", required=True, help="Path to public key file")
    args = parser.parse_args()

    try:
        symmetric_key = readfile(args.symmetric_key)
        if len(symmetric_key) == 0:
            symmetric_key = symmetric_key_generation()
        asymmetric_keys = asymmetric_keys_generation()
        asymmetric_keys_writter(args.secret_key, args.public_key, asymmetric_keys)
        encrypted_key = key_encription(symmetric_key, asymmetric_keys[1], args.secret_key)
        symmetric_key_writter(args.symmetric_key, encrypted_key)
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()