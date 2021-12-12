from string import *
import hashlib as hl
import pandas as pd

def createUsername(username):
    usernameInvalid = any(c not in usernameReq for c in username)
    usernameLength = len(username)
    usernameTaken = any(userdata["username"].str.lower() == username.lower())

    if usernameInvalid:
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

    if passwordInvalid:
        return "invalidPassword"
    elif passwordLength < 8:
        return "shortPassword"
    elif passwordLength > 32:
        return "longPassword"
    elif passwordInsecure:
        return "insecurePassword"
    else:
        return "success"

def changePassword(username, password):
    password = hl.sha256(password.encode()).hexdigest()
    userdata.loc[userdata["username"] == username, "password"] = password
    save(userdata)

def registerUser(username, password):
    defaultData = {
        "username": username,
        "password": hl.sha256(password.encode()).hexdigest()
    }

    data = userdata.append(defaultData, ignore_index = True)
    save(data)

def read():
    global userdata
    userdata = pd.read_excel("userdata.xlsx")

def save(data):
    data.set_index("username").sort_index().to_excel("userdata.xlsx")
    read()

usernameReq = ascii_letters + digits + "_-."
passwordReq = ascii_letters + digits + punctuation

read()