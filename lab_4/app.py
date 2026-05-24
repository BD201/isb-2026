import argparse
from fileworks import read_json, json_writter
from without_salt import hash_without_salt, sign_in_without_salt
from with_salt import hash, sign_in
from registration import registration

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-j", "--json_file", type=str, default="settings.json", help="Json file with settings")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-r", "--registration", action="store_true", help="Choose registration mode")
    group.add_argument("-s", "--sign_in", action="store_true", help="Choose sign in mode")

    group_storage = parser.add_mutually_exclusive_group(required=True)
    group_storage.add_argument("-o", "--old_storage", action="store_true", help="Storage without salt")
    group_storage.add_argument("-n", "--new_storage", action="store_true", help="Storage with salt")

    parser.add_argument("-l", "--login", help="User's login")
    parser.add_argument("-p", "--password", help="User's password")
    args = parser.parse_args()
    
    try:
        paths = read_json(args.json_file)
        match args:
            case _ if args.old_storage:
                storage = paths["storage_file_without_salt"]
                data = read_json(storage)
            case _ if args.new_storage:
                storage = paths["storage_file"]
                data = read_json(storage)
        match args:
            case _ if args.registration:
                match args:
                    case _ if args.old_storage:
                        hashed = hash_without_salt(args.password)
                    case _ if args.new_storage:
                        hashed = hash(args.password)
                if registration(args.login, hashed, data):
                    print("Registration success.")
                    json_writter(storage, data)
            case _ if args.sign_in:
                match args:
                    case _ if args.old_storage:
                        if sign_in_without_salt(args.login, args.password, data):
                           print("Sign in success")
                    case _ if args.new_storage:
                        if sign_in(args.login, args.password, data):
                           print("Sign in success")
    except Exception as e:
        print(e)
  

if __name__ == "__main__":
    main()