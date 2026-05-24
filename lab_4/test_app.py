import pytest
import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.dirname(__file__))

from without_salt import hash_without_salt, sign_in_without_salt
from with_salt import hash, sign_in
from registration import registration
from fileworks import read_json, json_writter


def test_hash_without_salt():
    r = hash_without_salt("pass")
    assert len(r) == 64
    assert isinstance(r, str)


def test_hash_with_salt():
    r = hash("pass")
    assert len(r) == 60
    assert r.startswith("$2b$")


def test_registration_success():
    data = {}
    assert registration("user", "hash", data) is True
    assert "user" in data


def test_registration_exists():
    data = {"user": "old"}
    assert registration("user", "new", data) is False


def test_sign_in_without_salt_ok():
    data = {"u": hash_without_salt("123")}
    assert sign_in_without_salt("u", "123", data) is True


def test_sign_in_without_salt_fail():
    data = {"u": hash_without_salt("123")}
    assert sign_in_without_salt("u", "wrong", data) is False


def test_sign_in_without_salt_not_exists():
    data = {}
    assert sign_in_without_salt("nonexist", "pass", data) is False


def test_sign_in_with_salt_ok():
    data = {"u": hash("123")}
    assert sign_in("u", "123", data) is True


def test_sign_in_with_salt_fail():
    data = {"u": hash("123")}
    assert sign_in("u", "wrong", data) is False


def test_sign_in_with_salt_not_exists():
    data = {}
    assert sign_in("nonexist", "pass", data) is False


def test_registration_empty_login():
    data = {}
    assert registration("", "hash", data) is False


def test_registration_empty_password():
    data = {}
    assert registration("user", "", data) is False


def test_read_json_file_exists():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({"test": "value"}, f)
        f.flush()
        filename = f.name
    
    data = read_json(filename)
    assert data == {"test": "value"}
    os.unlink(filename)


def test_read_json_file_not_exists():
    data = read_json("nonexistent_file_12345.json")
    assert data == {}


def test_read_json_empty_file():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write("")
        f.flush()
        filename = f.name
    
    data = read_json(filename)
    assert data == {}
    os.unlink(filename)


def test_read_json_invalid_json():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write("{invalid json")
        f.flush()
        filename = f.name
    
    with pytest.raises(Exception):
        read_json(filename)
    os.unlink(filename)


def test_json_writter():
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        filename = f.name
    
    test_data = {"user1": "hash123", "user2": "hash456"}
    json_writter(filename, test_data)
    
    with open(filename, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    assert data == test_data
    os.unlink(filename)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=without_salt", "--cov=with_salt", "--cov=registration", "--cov=fileworks", "--cov-report=term"])