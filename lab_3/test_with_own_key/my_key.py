import os

my_key = os.urandom(32)

with open("lab_3/test_with_own_key/my_key.txt", "wb") as file:
    file.write(my_key)