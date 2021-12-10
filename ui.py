from PyQt6.QtWidgets import *
from user import *

class UI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Database")
        self.setGeometry(0, 0, 400, 300)

        self.userWidget = QWidget(self)
        self.setCentralWidget(self.userWidget)

        self.userLayout = QVBoxLayout(self.userWidget)
        self.userInputFrame = QFrame(self.userWidget)
        self.userButtonFrame = QFrame(self.userWidget)
        self.userHiddenFrame1 = QFrame(self.userWidget)
        self.userHiddenFrame2 = QFrame(self.userWidget)
        
        self.userLayout.addWidget(self.userInputFrame)
        self.userLayout.addWidget(self.userButtonFrame)
        self.userLayout.addWidget(self.userHiddenFrame1)
        self.userLayout.addWidget(self.userHiddenFrame2)

        self.userInputLayout = QGridLayout(self.userInputFrame)
        self.userButtonLayout = QHBoxLayout(self.userButtonFrame)
        
        self.usernameLabel = QLabel(self.userInputFrame)
        self.usernameLabel.setText("Username:")
        self.usernameLineEdit = QLineEdit(self.userInputFrame)
        self.passwordLabel = QLabel(self.userInputFrame)
        self.passwordLabel.setText("Password:")
        self.passwordLineEdit = QLineEdit(self.userInputFrame)
        self.passwordLineEdit.setEchoMode(QLineEdit.EchoMode.Password)

        self.userInputLayout.addWidget(self.usernameLabel, 1, 1, 1, 1)
        self.userInputLayout.addWidget(self.usernameLineEdit, 1, 2, 1, 1)
        self.userInputLayout.addWidget(self.passwordLabel, 2, 1, 1, 1)
        self.userInputLayout.addWidget(self.passwordLineEdit, 2, 2, 1, 1)

        self.userLoginButton = QPushButton(self.userButtonFrame)
        self.userLoginButton.clicked.connect(lambda: self.loginClicked(self.usernameLineEdit.text(), self.passwordLineEdit.text()))
        self.userLoginButton.setText("Login")
        self.userRegisterButton = QPushButton(self.userButtonFrame)
        self.userRegisterButton.clicked.connect(lambda: self.registerClicked(self.usernameLineEdit.text(), self.passwordLineEdit.text()))
        self.userRegisterButton.setText("Register")

        self.userButtonLayout.addWidget(self.userLoginButton)
        self.userButtonLayout.addWidget(self.userRegisterButton)

        self.dataWidget = QWidget(self)

        self.dataLayout = QVBoxLayout(self.dataWidget)
        self.dataDisplayFrame = QFrame(self.dataWidget)
        self.dataStorageFrame = QFrame(self.dataWidget)

        self.dataLayout.addWidget(self.dataDisplayFrame)
        self.dataLayout.addWidget(self.dataStorageFrame)

        self.dataDisplayLayout = QGridLayout(self.dataDisplayFrame)
        self.dataStorageLayout = QVBoxLayout(self.dataStorageFrame)

        self.currentUsernameLabel = QLabel(self.dataDisplayFrame)
        self.currentUsernameLabel.setText("Username:")
        self.currentUsernameDisplayLabel = QLabel(self.dataDisplayFrame)
        self.newPasswordLabel = QLabel(self.dataDisplayFrame)
        self.newPasswordLabel.setText("Password:")
        self.newPasswordLineEdit = QLineEdit(self.dataDisplayFrame)
        self.newPasswordLineEdit.setEchoMode(QLineEdit.EchoMode.Password)
        self.changePasswordButton = QPushButton(self.dataDisplayFrame)
        self.changePasswordButton.setText("Change")

        self.dataDisplayLayout.addWidget(self.currentUsernameLabel, 1, 1, 1, 1)
        self.dataDisplayLayout.addWidget(self.currentUsernameDisplayLabel, 1, 2, 1, 1)
        self.dataDisplayLayout.addWidget(self.newPasswordLabel, 2, 1, 1, 1)
        self.dataDisplayLayout.addWidget(self.newPasswordLineEdit, 2, 2, 1, 1)
        self.dataDisplayLayout.addWidget(self.changePasswordButton, 2, 3, 1, 1)

        self.dataStorageTextEdit = QTextEdit(self.dataStorageFrame)

        self.dataStorageLayout.addWidget(self.dataStorageTextEdit)

        self.dataWidget.hide()

    def loginClicked(self, username, password):
        usernameMatched = (userdata["username"].str.lower() == username.lower())

        if any(usernameMatched):
            username = userdata.loc[usernameMatched, "username"].item()
            if hl.sha256(password.encode()).hexdigest() == userdata.loc[usernameMatched, "password"].item():
                print("Logged in successfully!")
                self.loginUser(username)
            else:
                self.error("invalidCredentials")
        else:
            self.error("invalidCredentials")

    def registerClicked(self, username, password):
        if createUsername(username) == "success":
            if createPassword(password) == "success":
                print("Registered successfully!")
                registerUser(username, password)
                self.loginUser(username)
            else:
                self.error(createPassword(password))
        else:
            self.error(createUsername(username))

    def loginUser(self, username):
        self.userWidget.hide()
        self.dataWidget.show()
        self.setCentralWidget(self.dataWidget)
        self.currentUsernameDisplayLabel.setText(username)
    
    def error(self, id):
        if id == "invalidCredentials":
            print("Credentials are invalid!")
        elif id == "invalidUsername":
            print("Username contains invalid characters!")
        elif id == "shortUsername":
            print("Username must be at least 3 characters!")
        elif id == "longUsername":
            print("Username must be at most 16 characters!")
        elif id == "unavailableUsername":
            print("Username is unavailable!")
        elif id == "invalidPassword":
            print("Password contains invalid characters!")
        elif id == "shortPassword":
            print("Password must be at least 8 characters")
        elif id == "longPassword":
            print("Password must be at most 32 characters!")
        elif id == "insecurePassword":
            print("Password is insecure!")
