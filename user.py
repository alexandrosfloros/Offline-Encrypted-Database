from string import *
import hashlib as hl
from base64 import urlsafe_b64encode, urlsafe_b64decode
import pandas as pd

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
    passwordInsecure = not any(c in ascii_lowercase for c in password) or not any(c in ascii_uppercase for c in password) \
    or not any(c in digits for c in password) or not any(c in punctuation for c in password)

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
        if hl.sha256(password.encode()).hexdigest() == userdata.loc[usernameMatched, "password"].item():
            return "success"
        else:
            return "invalidCredentials"
    else:
        return "invalidCredentials"

def changePassword(username, password, userdata):
    password = hl.sha256(password.encode()).hexdigest()
    userdata.loc[userdata["username"] == username, "password"] = password
    saveData(userdata)

def saveContent(username, password, content, userdata):
    content = encryptData(content, password)

    userdata.loc[userdata["username"] == username, "content"] = content
    saveData(userdata)

def registerUser(username, password, userdata):
    defaultData = {
        "username": username.lower(),
        "password": hl.sha256(password.encode()).hexdigest()
    }

    userdata = userdata.append(defaultData, ignore_index = True)
    
    saveData(userdata)

def saveData(userdata):
    userdata.set_index("username").sort_index().to_excel("userdata.xlsx")

def encryptData(content, password):
    return urlsafe_b64encode(bytes(password + content, "utf-8"))

def decryptData(content, password):
    return urlsafe_b64decode(bytes(content[2:-1], "utf-8"))[len(password):].decode("utf-8")

usernameReq = ascii_letters + digits + "_-."
passwordReq = ascii_letters + digits + punctuation