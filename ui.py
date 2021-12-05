from PyQt6.QtWidgets import *
import hashlib as hl
from user import *

class UI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Database")
        self.setGeometry(0, 0, 400, 300)

        self.userLayout = QVBoxLayout(self)
        self.userInputFrame = QFrame(self)
        self.userButtonFrame = QFrame(self)
        self.userHiddenFrame1 = QFrame(self)
        self.userHiddenFrame2 = QFrame(self)
        
        self.userLayout.addWidget(self.userInputFrame)
        self.userLayout.addWidget(self.userButtonFrame)
        self.userLayout.addWidget(self.userHiddenFrame1)
        self.userLayout.addWidget(self.userHiddenFrame2)

        self.userInputLayout = QGridLayout(self.userInputFrame)
        self.userButtonLayout = QHBoxLayout(self.userButtonFrame)
        
        self.usernameLabel = QLabel(self.userInputFrame)
        self.usernameLabel.setText("Username:")
        self.passwordLabel = QLabel(self.userInputFrame)
        self.passwordLabel.setText("Password:")
        self.usernameEntry = QLineEdit(self.userInputFrame)
        self.passwordEntry = QLineEdit(self.userInputFrame)
        self.passwordEntry.setEchoMode(QLineEdit.EchoMode.Password)

        self.userInputLayout.addWidget(self.usernameLabel, 1, 1, 1, 1)
        self.userInputLayout.addWidget(self.passwordLabel, 2, 1, 1, 1)
        self.userInputLayout.addWidget(self.usernameEntry, 1, 2, 1, 1)
        self.userInputLayout.addWidget(self.passwordEntry, 2, 2, 1, 1)

        self.userLoginButton = QPushButton(self.userButtonFrame)
        self.userLoginButton.clicked.connect(self.loginClicked)
        self.userLoginButton.setText("Login")
        self.userRegisterButton = QPushButton(self.userButtonFrame)
        self.userRegisterButton.clicked.connect(self.registerClicked)
        self.userRegisterButton.setText("Register")

        self.userButtonLayout.addWidget(self.userLoginButton)
        self.userButtonLayout.addWidget(self.userRegisterButton)

    def loginClicked(self):
        username = self.usernameEntry.text()
        password = self.passwordEntry.text()

        if (username.lower() in userdata["username"].values) and (hl.sha256(password.encode()).hexdigest() == userdata.set_index("username").loc[username.lower(), "password"]):
            print("Logged in successfully!")
            self.loginUser(username, password)
        else:
            print("Credentials are invalid!")

    def registerClicked(self):
        global userdata

        username = self.usernameEntry.text()
        password = self.passwordEntry.text()

        usernameInvalid = any(c not in usernameReq for c in username)
        usernameLength = len(username)
        usernameTaken = any(userdata["username"] == username.lower())

        passwordInvalid = any(c not in passwordReq for c in password)
        passwordLength = len(password)
        passwordInsecure = not any(c in ascii_lowercase for c in password) or not any(c in ascii_uppercase for c in password) or not any(c in digits for c in password) or not any(c in punctuation for c in password)
        
        if usernameInvalid:
            print("Username contains invalid characters!")
        elif usernameLength < 3:
            print("Username must be at least 3 characters!")
        elif usernameLength > 16:
            print("Username must be at most 16 characters!")
        elif usernameTaken:
            print("Username already taken!")
        else:
            if passwordInvalid:
                print("Password contains invalid characters!")
            elif passwordLength < 8:
                print("Password must be at least 8 characters")
            elif passwordLength > 32:
                print("Password must be at most 32 characters!")
            elif passwordInsecure:
                print("Password not secure!")
            else:
                print("Registered successfully!")
                self.registerUser(username, password)

    def registerUser(self, username, password):
        global userdata

        defaultData = {
            "username": username,
            "password": hl.sha256(password.encode()).hexdigest()
        }

        userdata = userdata.append(defaultData, ignore_index = True)
        print(userdata.set_index("username"))
        userdata.set_index("username").sort_index().to_excel("userdata.xlsx")

    def loginUser(self, username, password):
        pass