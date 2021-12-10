from string import *
import hashlib as hl
import pandas as pd
usernameReq = ascii_letters + digits + "_-."
passwordReq = ascii_letters + digits + punctuation

userdata = pd.read_excel("userdata.xlsx")

def registerUser(username, password):
    global userdata

    defaultData = {
        "username": username,
        "password": hl.sha256(password.encode()).hexdigest()
    }

    userdata = userdata.append(defaultData, ignore_index = True)
    userdata.set_index("username").sort_index().to_excel("userdata.xlsx")