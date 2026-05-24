import os
import json

def read_json(filename: str) -> dict:
    """
    Read data from json file

    Args:
        filename: Path to the JSON file to read
    
    Returns:
        dict: Parsed JSON data as a dictionary
    """
    try:
        if os.path.getsize(filename) == 0:
            return {}
        with open(filename) as file:
            return json.load(file)
    except FileNotFoundError:
        return {}
    except Exception as e:
        raise e  


def json_writter(filename: str, data: dict):
    """
    Write dict to json file

    Args: 
        filename: name of json file
        data: dict of logins and passwords
    """
    with open(filename, 'w') as fp:
        json.dump(data, fp, indent=4, ensure_ascii=False)