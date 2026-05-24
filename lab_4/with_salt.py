import bcrypt

def hash(password: str) -> str:
    """
    Hashes the password with salt

    Args:
        password: original password

    Returns:
        hashed password
    """
    b_password = password.encode('utf-8')
    return bcrypt.hashpw(b_password, bcrypt.gensalt()).decode('utf-8')


def sign_in(login: str, password: str, data: dict) -> bool:
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
        b_password = password.encode('utf-8')
        data_password = data[login]
        if not bcrypt.checkpw(b_password, data_password.encode('utf-8')):
            raise Exception("Password is not correct")  
        return True
    except Exception as e:
        print(e)
        return False