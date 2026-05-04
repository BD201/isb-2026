import argparse
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from fileworks import read_str, read_bytes, str_writer, encrypted_ChaCha20_writer


def get_secret_key(filename: str):
    """
    Read asymmetric key from file

    Args:
        filename: Path to the pem private key file
    
    Returns:
        Private key
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

    Args:
        key: Encrypted symmetric key bytes
        secret_key: Private key
    
    Returns:
        bytes: Decrypted symmetric key
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

    Args:
        text: Plain text string to encrypt
        key: 32-byte symmetric key for encryption
    
    Returns:
        tuple: (encrypted_text_bytes, nonce_bytes)
    
    Raises:
        ValueError: If key length is not 32 bytes
    """
    if len(key) != 32:
        raise ValueError(f"Key length must be 32. Your key length - {len(key)}")
    
    nonce = os.urandom(8)
    counter = 0
    full_nonce = counter.to_bytes(8, 'little') + nonce

    cipher = Cipher(algorithms.ChaCha20(key, full_nonce), mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(text.encode('utf-8')), nonce


def text_decryption(c_text: bytes, key: bytes) -> str:
    """
    Encryption text with ChaCha20

    Args:
        c_text: Encrypted bytes where first 8 bytes are nonce
        key: 32-byte symmetric key for decryption
    
    Returns:
        str: Decrypted plain text
    
    Raises:
        ValueError: If key length is not 32 bytes or encrypted text is too short
    """
    if len(key) != 32:
        raise ValueError(f"Key length must be 32. Your key length - {len(key)}")
    
    
    if len(c_text) < 8:
        raise ValueError(f"Encrypted text length must higher than 8. Your text length - {len(key)}")
    
    nonce = c_text[:8]
    c_text = c_text[8:]
    counter = 0
    full_nonce = counter.to_bytes(8, 'little') + nonce

    cipher = Cipher(algorithms.ChaCha20(key, full_nonce), mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(c_text).decode('utf-8')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input_file", required=True, help="Readable text file")
    parser.add_argument("-k", "--key_file", required=True, help="Text file containing key")
    parser.add_argument("-s", "--secret_key_file", required=True, help="Text file containing key")
    parser.add_argument("-o", "--output_file", required=True, help="Result text file")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encryption", action="store_true", help="Start encryption")
    group.add_argument("-d", "--decryption", action="store_true", help="Start encryption")
    args = parser.parse_args()

    try:
        key = read_bytes(args.key_file)
        secret_key = get_secret_key(args.secret_key_file)
        key = decrypt_key(key, secret_key)

        match args:
            case _ if args.encryption:
                text = read_str(args.input_file)
                result_text, nonce = text_encryption(text, key)
                encrypted_ChaCha20_writer(result_text, nonce, args.output_file)
            case _ if args.decryption:
                text = read_bytes(args.input_file)
                result_text = text_decryption(text, key)
                str_writer(result_text, args.output_file)

    except Exception as e:
        print(f"Error {e}")


if __name__ == "__main__":
    main()