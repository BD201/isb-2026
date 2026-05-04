import argparse
import sys
from fileworks import read_json, run_py 

def run_generation(run_file: str, symmetric_key: str, secret_key: str, public_key: str):
    """
    Run key generation file

    Args:
        run_file: Path to the key generation Python script
        symmetric_key: Path where symmetric key will be saved
        secret_key: Path where private (secret) key will be saved
        public_key: Path where public key will be saved
    """
    run_py([sys.executable, run_file, "-sy", symmetric_key, "-s", secret_key, "-p", public_key])


def run_cryption(run_file: str, input: str, key: str, key_for_key: str, output: str, mode: str):
    """
    Run text encryption or decryption
    
    Args:
        run_file: Path to the encryption/decryption Python script
        input: Path to input file (plaintext for encryption, ciphertext for decryption)
        key: Path to symmetric key file
        key_for_key: Path to private key file for decrypting the symmetric key
        output: Path to output file (ciphertext for encryption, plaintext for decryption)
        mode: Operation mode - "-e" for encryption or "-d" for decryption
    """
    if mode != '-e' and mode != '-d':
        raise RuntimeError("Not correct mode.")
    run_py([sys.executable, run_file, "-i", input, "-k", key, "-s", key_for_key, "-o", output, mode])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-j", "--json_file", type=str, default="settings.json", help="Json file with keys, modules and texts paths")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-g", "--generation", action="store_true", help="Start key generation")
    group.add_argument("-e", "--encryption", action="store_true", help="Start encryption")
    group.add_argument("-d", "--decryption", action="store_true", help="Start encryption")
    
    parser.add_argument("-sy", "--symmetric_key", help="Path to user's symmetric key")

    args = parser.parse_args()
    
    paths = read_json(args.json_file)

    match args:
        case _ if args.generation:
            symmetric_key = paths["symmetric_key"] if not args.symmetric_key else args.symmetric_key
            run_generation(paths["generation_file"], symmetric_key, paths["secret_key"], paths["public_key"])
        case _ if args.encryption:
            symmetric_key = paths["symmetric_key"] if not args.symmetric_key else args.symmetric_key
            run_cryption(paths["cryption_file"], paths["initial_file"], symmetric_key, paths["secret_key"], paths["encrypted_file"], "-e")
        case _ if args.decryption: 
            symmetric_key = paths["symmetric_key"] if not args.symmetric_key else args.symmetric_key
            run_cryption(paths["cryption_file"], paths["encrypted_file"], symmetric_key, paths["secret_key"], paths["decrypted_file"], "-d") 


if __name__ == "__main__":
    main()