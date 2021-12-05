from string import *
import pandas as pd
usernameReq = ascii_letters + digits + "_-."
passwordReq = ascii_letters + digits + punctuation

userdata = pd.read_excel("userdata.xlsx")
print(userdata.set_index("username"))