from string import *
import hashlib as hl
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
    if isinstance(content, str):
        content = encryptContent(content, password, 1)
    else:
        content = ""

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

def cipherShift(char, shift):
    return cipherAlphabet[(cipherAlphabet.find(char) + shift) % 95]

def encryptContent(content, key, mode):
    keyLength = len(key)
    out = ""

    for n, char in enumerate(content):
        if char in cipherAlphabet:
            m = n % keyLength
            shift = printable.find(key[m])
            out += cipherShift(char, shift * mode)
        else:
            out += char
    return out

usernameReq = ascii_letters + digits + "_-."
passwordReq = ascii_letters + digits + punctuation
cipherAlphabet = printable[:-5]