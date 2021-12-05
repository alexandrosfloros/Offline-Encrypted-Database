import sys
from ui import *

def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    ui = UI()
    ui.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()