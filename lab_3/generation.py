import argparse
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from fileworks import read_bytes

def symmetric_key_generation()->bytes:
    """
    Generate symmetric keys

    Returns:
        bytes: Random 32-byte symmetric key
    """
    key = os.urandom(32)
    return key


def asymmetric_keys_generation():
    """
    Generate asymmetric keys

    Returns:
        tuple: (private_key, public_key) where private_key is RSA private key and public_key is corresponding RSA public key
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
    Write secret key in pem file

    Args:
        secret_pem: Path to output private key file
        private_key: Private key to write
    """
    with open(secret_pem, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
              format=serialization.PrivateFormat.TraditionalOpenSSL,
              encryption_algorithm=serialization.NoEncryption()))


def public_key_writter(public_pem: str, public_key: bytes):
    """
    Write public key in pem file

    Args:
        public_pem: Path to output public key file
        public_key: Public key to write
    """
    with open(public_pem, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
             format=serialization.PublicFormat.SubjectPublicKeyInfo))


def asymmetric_keys_writter(secret_pem: str, public_pem: str, asymmetric_keys: tuple):
    """
    Write asymmetric keys

    Args:
        secret_pem: Path to output private key file
        public_pem: Path to output public key file
        asymmetric_keys: Tuple containing (private_key, public_key)
    """
    secret_key_writter(secret_pem, asymmetric_keys[0])
    public_key_writter(public_pem, asymmetric_keys[1])


def key_encription(symmetric_key: bytes, public_key: bytes):
    """
    Symmetric key encryption

    Args:
        symmetric_key: Symmetric key bytes
        public_key: Public key for encryption
    
    Returns:
        bytes: Encrypted symmetric key
    """
    try:
        return public_key.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    except ValueError:
        symmetric_key = symmetric_key_generation()
        return public_key.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))


def symmetric_key_writter(filepath: str, symmetric_key: bytes):
    """
    Write symmetric key

    Args:
        filepath: Path to output file
        symmetric_key: Symmetric key bytes to write
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
        try:
            symmetric_key = read_bytes(args.symmetric_key)
        except FileNotFoundError:
            symmetric_key = symmetric_key_generation()
        asymmetric_keys = asymmetric_keys_generation()
        asymmetric_keys_writter(args.secret_key, args.public_key, asymmetric_keys)
        encrypted_key = key_encription(symmetric_key, asymmetric_keys[1])
        symmetric_key_writter(args.symmetric_key, encrypted_key)
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()