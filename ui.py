from PyQt6.QtWidgets import *
from user import *

class UI(QMainWindow):
    def __init__(self):
        self.readData()

        super().__init__()
        self.setWindowTitle("Offline Encrypted Database")
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
        self.loginButton.clicked.connect(self.loginClicked)
        self.loginButton.setText("Login")
        self.registerButton = QPushButton(self.userButtonFrame)
        self.registerButton.clicked.connect(self.registerClicked)
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
        self.changePasswordButton.clicked.connect(self.changePasswordClicked)
        self.changePasswordButton.setText("Change")

        self.dataDisplayLayout.addWidget(self.currentUsernameLabel, 1, 1, 1, 1)
        self.dataDisplayLayout.addWidget(self.currentUsernameDisplayLabel, 1, 2, 1, 1)
        self.dataDisplayLayout.addWidget(self.newPasswordLabel, 2, 1, 1, 1)
        self.dataDisplayLayout.addWidget(self.newPasswordLineEdit, 2, 2, 1, 1)
        self.dataDisplayLayout.addWidget(self.changePasswordButton, 2, 3, 1, 1)

        self.dataStorageTextEdit = QTextEdit(self.dataStorageFrame)

        self.dataStorageLayout.addWidget(self.dataStorageTextEdit)

        self.saveContentButton = QPushButton(self.dataButtonFrame)
        self.saveContentButton.clicked.connect(self.saveClicked)
        self.saveContentButton.setText("Save and Logout")
        self.logoutButton = QPushButton(self.dataButtonFrame)
        self.logoutButton.clicked.connect(self.userPage)
        self.logoutButton.setText("Logout")

        self.dataButtonLayout.addWidget(self.saveContentButton)
        self.dataButtonLayout.addWidget(self.logoutButton)

    def loginClicked(self):
        username = self.usernameLineEdit.text()
        password = self.passwordLineEdit.text()
        userdata = self.userdata

        if loginUser(username, password, userdata) == "success":
            self.password = password
            self.dataPage(username)
        else:
            self.error(loginUser(username, password, userdata))

    def registerClicked(self):
        username = self.usernameLineEdit.text()
        password = self.passwordLineEdit.text()
        userdata = self.userdata

        if createUsername(username, userdata) == "success":
            if createPassword(password) == "success":
                registerUser(username, password, userdata)
                self.readData()

                self.password = password
                self.dataPage(username)
            else:
                self.error(createPassword(password))
        else:
            self.error(createUsername(username, userdata))
    
    def changePasswordClicked(self):
        username = self.currentUsernameDisplayLabel.text()
        password = self.newPasswordLineEdit.text()
        content = self.content
        userdata = self.userdata

        if createPassword(password) == "success":
            changePassword(username, password, userdata)
            self.password = password

            saveContent(username, password, content, userdata)
        else:
            self.error(createPassword(password))
    
    def saveClicked(self):
        username = self.currentUsernameDisplayLabel.text()
        password = self.password
        content = self.dataStorageTextEdit.toPlainText()
        userdata = self.userdata

        saveContent(username, password, content, userdata)
        self.content = content

        self.userPage()

    def dataPage(self, username):
        self.mainWidget.setCurrentWidget(self.dataWidget)
        self.currentUsernameDisplayLabel.setText(username.lower())
        self.content = self.userdata.loc[self.userdata["username"] == username.lower(), "content"].item()
        
        if pd.isna(self.content):
            self.dataStorageTextEdit.setText("")
        else:
            self.content = encryptContent(self.content, self.password, -1)
            self.dataStorageTextEdit.setText(self.content)
        
        self.usernameLineEdit.clear()
        self.passwordLineEdit.clear()

    def userPage(self):
        self.readData()
        self.mainWidget.setCurrentWidget(self.userWidget)
        self.newPasswordLineEdit.clear()
    
    def readData(self):
        self.userdata = pd.read_excel("userdata.xlsx")
    
    def error(self, id):
        if id == "invalidCredentials":
            message = "Credentials are invalid!"
        elif id == "noUsername":
            message = "Username is missing!"
        elif id == "noPassword":
            message = "Password is missing!"
        elif id == "invalidUsername":
            message = "Username contains invalid characters!"
        elif id == "shortUsername":
            message = "Username must be at least 3 characters!"
        elif id == "longUsername":
            message = "Username must be at most 16 characters!"
        elif id == "unavailableUsername":
            message = "Username is unavailable!"
        elif id == "invalidPassword":
            message = "Password contains invalid characters!"
        elif id == "shortPassword":
            message = "Password must be at least 8 characters"
        elif id == "longPassword":
            message = "Password must be at most 32 characters!"
        elif id == "insecurePassword":
            message = "Password must contain at least one lowercase character, one uppercase character, one number and one special character!"
        
        errorMessage = QMessageBox.critical(self, "Error", message)