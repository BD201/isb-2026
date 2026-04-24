import argparse
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def readfile(filename: str) -> str:
    """
    Read text file mode
    """
    try:
        with open(filename, encoding="UTF-8") as file:
            return file.read()
    except FileNotFoundError as e:
        print(f"Error: {e}")
        raise e


def get_key(filename: str) -> bytes:
    """
    Read symmetric key from file
    """
    try:
        with open(filename, mode='rb') as file:
            return file.read()
    except Exception as e:
        print(f"Error: {e}")
        raise e


def get_secret_key(filename: str):
    """
    Read asymmetric key from file
    """
    try:
        with open(filename, 'rb') as file:
            private_bytes = file.read()
        return load_pem_private_key(private_bytes,password=None,)
    except Exception as e:
        print(f"Error: {e}")
        raise e


def decrypt_key(key: bytes, secret_key: bytes) -> bytes:
    """
    Decryption of symmetric key
    """
    try:
        return secret_key.decrypt(key,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
    except ValueError:
        return key
    except Exception as e:
        print(f"Error: {e}")
        raise e
    

def text_encryption(text: str, key: bytes) -> tuple:
    """
    Encryption text with ChaCha20
    Return encrypted text and nonce
    """
    if len(key) != 32:
        raise ValueError(f"Key length must be 32. Your key length - {len(key)}")
    
    nonce = os.urandom(8)
    counter = 0
    full_nonce = counter.to_bytes(8, 'little') + nonce

    cipher = Cipher(algorithms.ChaCha20(key, full_nonce), mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(text.encode('utf-8')), nonce


def result_writer(text: bytes, nonce: str, filename: str):
    """
    Write encrypted text and nonce
    """
    try:
        with open(filename, 'wb') as file:
            file.write(nonce)
            file.write(text)
    except Exception as e:
        print(f"Error: {e}")
        raise e


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input_file", required=True, help="Readable text file")
    parser.add_argument("-k", "--key_file", required=True, help="Text file containing key")
    parser.add_argument("-s", "--secret_key_file", required=True, help="Text file containing key")
    parser.add_argument("-o", "--output_file", required=True, help="Result text file")
    args = parser.parse_args()

    try:
        text = readfile(args.input_file)
        key = get_key(args.key_file)
        secret_key = get_secret_key(args.secret_key_file)

        key = decrypt_key(key, secret_key)
        result_text, nonce = text_encryption(text, key)
        result_writer(result_text, nonce, args.output_file)
    except Exception as e:
        print(f"Error {e}")



if __name__ == "__main__":
    main()