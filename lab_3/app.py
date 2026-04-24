import json
import argparse
import os
import sys
import subprocess


def read_json(filename: str) -> dict:
    """
    Read data from json file
    """
    try:
        if not filename.endswith(".json"):
            filename += ".json"
        with open(filename) as json_file:
            data = json.load(json_file)
        return data
    except Exception as e:
        print(e)
        raise e


def run_py(args: list[str]):
    """
    Run python file
    """
    run_file = args[1]
    if not os.path.exists(run_file):
        raise FileNotFoundError(f"Error: file {run_file} is not found")
    try:
        result = subprocess.run(args)
        if result.returncode != 0:
            raise RuntimeError(f"Error: {result.returncode}")
    except Exception as e:
        raise RuntimeError(f"Error: file {run_file} is not correct")


def run_generation(run_file: str, symmetric_key: str, secret_key: str, public_key: str):
    """
    Run key generation file
    """
    run_py([sys.executable, run_file, "-sy", symmetric_key, "-s", secret_key, "-p", public_key])


def run_encryption(run_file: str, input: str, key: str, key_for_key: str, output: str):
    """
    Run text encryption
    """
    run_py([sys.executable, run_file, "-i", input, "-k", key, "-s", key_for_key, "-o", output])


def run_decryption(run_file: str, input: str, key: str, key_for_key: str,  output: str):
    """
    Run text decryption
    """
    run_py([sys.executable, run_file, "-i", input, "-k", key, "-s", key_for_key, "-o", output])


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

    if args.generation:
        symmetric_key = paths["symmetric_key"] if not args.symmetric_key else args.symmetric_key
        run_generation(paths["generation_file"], symmetric_key, paths["secret_key"], paths["public_key"])
    else:
        if args.encryption:
            symmetric_key = paths["symmetric_key"] if not args.symmetric_key else args.symmetric_key
            run_encryption(paths["encryption_file"], paths["initial_file"], symmetric_key, paths["secret_key"], paths["encrypted_file"])
        else:
            symmetric_key = paths["symmetric_key"] if not args.symmetric_key else args.symmetric_key
            run_decryption(paths["decryption_file"], paths["encrypted_file"], symmetric_key, paths["secret_key"], paths["decrypted_file"]) 


if __name__ == "__main__":
    main()