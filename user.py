import string
import hashlib
import base64
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
    passwordInsecure = not any(c in string.ascii_lowercase for c in password) or not any(c in string.ascii_uppercase for c in password) \
    or not any(c in string.digits for c in password) or not any(c in string.punctuation for c in password)

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
    usernameMatched = (userdata["username"] == username.lower())

    if any(usernameMatched):
        if hashlib.sha256(password.encode()).hexdigest() == userdata.loc[usernameMatched, "password"].item():
            return "success"
        else:
            return "invalidCredentials"
    else:
        return "invalidCredentials"

def changePassword(username, password, userdata):
    password = hashlib.sha256(password.encode()).hexdigest()
    userdata.loc[userdata["username"] == username, "password"] = password
    saveData(userdata)

def saveContent(username, password, content, userdata):
    if isinstance(content, str):
        content = encryptContent(content, password, "encrypt")
    else:
        content = ""

    userdata.loc[userdata["username"] == username, "content"] = content
    saveData(userdata)

def registerUser(username, password, userdata):
    defaultData = {
        "username": username.lower(),
        "password": hashlib.sha256(password.encode()).hexdigest()
    }

    userdata = userdata.append(defaultData, ignore_index = True)
    
    saveData(userdata)

def saveData(userdata):
    userdata.set_index("username").sort_index().to_excel("userdata.xlsx")

def encryptContent(content, password, mode):
    kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = salt, iterations = 390000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    fernet = Fernet(key)

    if mode == "encrypt":
        return fernet.encrypt(content.encode()).decode()
    else:
        return fernet.decrypt(content.encode()).decode()

usernameReq = string.ascii_letters + string.digits + "_-."
passwordReq = string.ascii_letters + string.digits + string.punctuation

salt = b"\x8aO%kR\xe32l\xf6\x00\x99\x13\xb0\xbdb\x9c"