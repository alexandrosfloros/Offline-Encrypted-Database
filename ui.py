from PyQt6.QtWidgets import *
from user import *

class UI(QMainWindow):
    def __init__(self):
        self.readData()

        super().__init__()
        self.setWindowTitle("Database")
        self.setGeometry(0, 0, 400, 300)

        self.mainWidget = QStackedWidget(self)
        self.setCentralWidget(self.mainWidget)

        self.userWidget = QWidget(self)
        self.dataWidget = QWidget(self)

        self.mainWidget.addWidget(self.userWidget)
        self.mainWidget.addWidget(self.dataWidget)
        self.mainWidget.setCurrentWidget(self.userWidget)

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

        self.loginButton = QPushButton(self.userButtonFrame)
        self.loginButton.clicked.connect(lambda: self.loginClicked(self.usernameLineEdit.text(), self.passwordLineEdit.text()))
        self.loginButton.setText("Login")
        self.registerButton = QPushButton(self.userButtonFrame)
        self.registerButton.clicked.connect(lambda: self.registerClicked(self.usernameLineEdit.text(), self.passwordLineEdit.text()))
        self.registerButton.setText("Register")

        self.userButtonLayout.addWidget(self.loginButton)
        self.userButtonLayout.addWidget(self.registerButton)

        self.dataLayout = QVBoxLayout(self.dataWidget)
        self.dataDisplayFrame = QFrame(self.dataWidget)
        self.dataStorageFrame = QFrame(self.dataWidget)
        self.dataButtonFrame = QFrame(self.dataWidget)

        self.dataLayout.addWidget(self.dataDisplayFrame)
        self.dataLayout.addWidget(self.dataStorageFrame)
        self.dataLayout.addWidget(self.dataButtonFrame)

        self.dataDisplayLayout = QGridLayout(self.dataDisplayFrame)
        self.dataStorageLayout = QVBoxLayout(self.dataStorageFrame)
        self.dataButtonLayout = QHBoxLayout(self.dataButtonFrame)

        self.currentUsernameLabel = QLabel(self.dataDisplayFrame)
        self.currentUsernameLabel.setText("Username:")
        self.currentUsernameDisplayLabel = QLabel(self.dataDisplayFrame)
        self.newPasswordLabel = QLabel(self.dataDisplayFrame)
        self.newPasswordLabel.setText("Password:")
        self.newPasswordLineEdit = QLineEdit(self.dataDisplayFrame)
        self.newPasswordLineEdit.setEchoMode(QLineEdit.EchoMode.Password)
        self.changePasswordButton = QPushButton(self.dataDisplayFrame)
        self.changePasswordButton.clicked.connect(lambda: self.changePasswordClicked(self.currentUsernameDisplayLabel.text(), self.newPasswordLineEdit.text()))
        self.changePasswordButton.setText("Change")

        self.dataDisplayLayout.addWidget(self.currentUsernameLabel, 1, 1, 1, 1)
        self.dataDisplayLayout.addWidget(self.currentUsernameDisplayLabel, 1, 2, 1, 1)
        self.dataDisplayLayout.addWidget(self.newPasswordLabel, 2, 1, 1, 1)
        self.dataDisplayLayout.addWidget(self.newPasswordLineEdit, 2, 2, 1, 1)
        self.dataDisplayLayout.addWidget(self.changePasswordButton, 2, 3, 1, 1)

        self.dataStorageTextEdit = QTextEdit(self.dataStorageFrame)

        self.dataStorageLayout.addWidget(self.dataStorageTextEdit)

        self.saveContentButton = QPushButton(self.dataButtonFrame)
        self.saveContentButton.clicked.connect(lambda: saveContent(self.currentUsernameDisplayLabel.text(), self.dataStorageTextEdit.toPlainText(), self.userdata))
        self.saveContentButton.setText("Save")
        self.logoutButton = QPushButton(self.dataButtonFrame)
        self.logoutButton.clicked.connect(self.userPage)
        self.logoutButton.setText("Logout")

        self.dataButtonLayout.addWidget(self.saveContentButton)
        self.dataButtonLayout.addWidget(self.logoutButton)

    def loginClicked(self, username, password):
        if loginUser(username, password, self.userdata) == "success":
            self.dataPage(username)
        else:
            self.error(loginUser(username, password, self.userdata))

    def registerClicked(self, username, password):
        if createUsername(username, self.userdata) == "success":
            if createPassword(password) == "success":
                registerUser(username, password, self.userdata)
                self.readData()
                self.dataPage(username)
            else:
                self.error(createPassword(password))
        else:
            self.error(createUsername(username))
    
    def changePasswordClicked(self, username, password):
        if createPassword(password) == "success":
            changePassword(username, password, self.userdata)
            self.readData()
        else:
            self.error(createPassword(password))
    
    def dataPage(self, username):
        self.mainWidget.setCurrentWidget(self.dataWidget)
        self.currentUsernameDisplayLabel.setText(username.lower())
        content = self.userdata.loc[self.userdata["username"] == username.lower(), "content"].item()
        if pd.isna(content):
            self.dataStorageTextEdit.setText("")
        else:
            self.dataStorageTextEdit.setText(content)
        self.usernameLineEdit.clear()
        self.passwordLineEdit.clear()

    def userPage(self):
        self.mainWidget.setCurrentWidget(self.userWidget)
        self.newPasswordLineEdit.clear()
    
    def readData(self):
        self.userdata = pd.read_excel("userdata.xlsx")
    
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