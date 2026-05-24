def registration(login: str, hashed_password: str, data: dict) -> bool:
    """
    User registration

    Args:
        login: user login
        hashed_password: user hashed password
        data: dict with logins and passwords

    Returns True if success, False otherwise
    """
    try:
        if not login or not hashed_password:
            raise Exception("Login and password can't be empty.")
        if login in data:
            raise Exception("This login already exists.")
        data[login] = hashed_password
        return True
    except Exception as e:
        print(e)
        return False