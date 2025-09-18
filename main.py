from gui import QApplication, LandingPage
import sys

#Run App
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LandingPage()
    window.show()
    sys.exit(app.exec_())