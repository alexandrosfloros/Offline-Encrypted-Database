import string
import hashlib
import base64
import os
import binascii
import pandas as pd

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def createUsername(username, userdata):
    usernameInvalid = any(c not in usernameReq for c in username)
    usernameLength = len(username)
    usernameTaken = any(userdata["username"] == username.lower())

    if usernameLength == 0:
        return "noUsername"

    elif usernameInvalid:
        return "invalidUsername"

    elif usernameLength < 3:
        return "shortUsername"

    elif usernameLength > 16:
        return "longUsername"

    elif usernameTaken:
        return "unavailableUsername"

    else:
        return "success"


def createPassword(password):
    passwordInvalid = any(c not in passwordReq for c in password)
    passwordLength = len(password)
    passwordInsecure = (
        not any(c in string.ascii_lowercase for c in password)
        or not any(c in string.ascii_uppercase for c in password)
        or not any(c in string.digits for c in password)
        or not any(c in string.punctuation for c in password)
    )

    if passwordLength == 0:
        return "noPassword"

    elif passwordInvalid:
        return "invalidPassword"

    elif passwordLength < 8:
        return "shortPassword"

    elif passwordLength > 32:
        return "longPassword"

    elif passwordInsecure:
        return "insecurePassword"

    else:
        return "success"


def loginUser(username, password, userdata):
    usernameMatched = userdata["username"] == username.lower()

    if any(usernameMatched):
        if (
            hashlib.sha256(password.encode()).hexdigest()
            == userdata.loc[usernameMatched, "password"].item()
        ):
            return "success"

        else:
            return "invalidCredentials"

    else:
        return "invalidCredentials"


def changePassword(username, password, userdata):
    password = hashlib.sha256(password.encode()).hexdigest()
    userdata.loc[userdata["username"] == username, "password"] = password
    writeData(userdata)


def saveData(username, password, content, userdata):
    if pd.isna(content):
        content = ""

    else:
        content = encryptContent(content, password, "encrypt")

    userdata.loc[userdata["username"] == username, "content"] = content
    writeData(userdata)


def registerUser(username, password, userdata):
    defaultData = pd.DataFrame(
        {
            "username": username.lower(),
            "password": hashlib.sha256(password.encode()).hexdigest(),
        },
        index=[0],
    )

    userdata = pd.concat([userdata, defaultData], ignore_index=True)

    writeData(userdata)


def writeData(userdata):
    userdata.set_index("username").sort_index().to_excel("userdata.xlsx")


def createKey(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    return Fernet(key)


def encryptContent(content, password, mode):
    if mode == "encrypt":
        salt = os.urandom(16)
        fernet = createKey(password, salt)

        return (
            binascii.b2a_hex(salt).decode() + fernet.encrypt(content.encode()).decode()
        )

    else:
        salt = binascii.a2b_hex(content[:32].encode())
        fernet = createKey(password, salt)

        return fernet.decrypt(content[32:].encode()).decode()


usernameReq = string.ascii_letters + string.digits + "_-."
passwordReq = string.ascii_letters + string.digits + string.punctuation
