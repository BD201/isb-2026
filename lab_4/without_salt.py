import hashlib

def hash_without_salt(password: str) -> str:
    """
    Hashes the password

    Args:
        password: original password

    Returns:
        hashed password
    """
    b_password = password.encode('utf-8')
    return hashlib.sha256(b_password).hexdigest()


def sign_in_without_salt(login: str, password: str, data: dict) -> bool:
    """
    User sign in

    Args:
        login: user login
        hashed_password: user hashed password
        data: dict with logins and passwords

    Returns True if success, False otherwise
    """
    try:
        if login not in data:
            raise Exception("Your login is not exists in system. Try fix login or register.")
        data_password = data[login]
        if hash_without_salt(password) != data_password:
            raise Exception("Password is not correct")  
        return True
    except Exception as e:
        print(e)
        return False