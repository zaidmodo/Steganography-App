import sys
import base64
import hashlib
import random
import os
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import Qt, QTimer, QPointF
from stegano import lsb
from cryptography.fernet import Fernet
from PIL import Image

class Particle(QLabel):
    def __init__(self, parent):
        super().__init__(parent)
        self.setStyleSheet("background-color: rgba(255,255,255, 0.4); border-radius: 4px;")
        self.resize(8, 8)
        self.move(random.randint(0, 960), random.randint(0, 600))
        self.speed = QPointF(random.uniform(-1, 1), random.uniform(-1, 1))

    def animate(self):
        pos = self.pos() + self.speed.toPoint()
        if pos.x() < 0 or pos.x() > 960:
            self.speed.setX(-self.speed.x())
        if pos.y() < 0 or pos.y() > 600:
            self.speed.setY(-self.speed.y())
        self.move(pos)

class SteganoApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Steganography Tool - Advanced & Stylish")
        self.setGeometry(100, 100, 960, 600)
        self.setFixedSize(960, 600)

        self.open_file = None
        self.hidden_image = None
        self.file_data = None
        self.file_name = None
        self.particles = []

        self.setup_ui()
        self.init_particles()

    def setup_ui(self):
        self.bg = QLabel(self)
        self.bg.setPixmap(QPixmap("abc.jpg").scaled(self.size(), Qt.IgnoreAspectRatio, Qt.SmoothTransformation))
        self.bg.setGeometry(0, 0, 960, 600)

        self.timer = QTimer()
        self.timer.timeout.connect(self.animate_particles)
        self.timer.start(30)

        self.image_label = QLabel(self)
        self.image_label.setGeometry(30, 50, 360, 270)
        self.image_label.setStyleSheet("border: 2px solid #00ffff; border-radius: 10px;")
        self.image_label.setAlignment(Qt.AlignCenter)

        self.text_box = QTextEdit(self)
        self.text_box.setGeometry(420, 50, 510, 200)
        self.text_box.setStyleSheet("""
            QTextEdit {
                background-color: rgba(30, 30, 30, 150);
                color: white;
                border-radius: 10px;
                font-size: 16px;
                padding: 10px;
            }
        """)
        self.text_box.setPlaceholderText("Enter The Text To Be Written")

        self.secret_key = QLineEdit(self)
        self.secret_key.setGeometry(420, 270, 300, 30)
        self.secret_key.setPlaceholderText("Enter Secret Key")
        self.secret_key.setEchoMode(QLineEdit.Password)
        self.secret_key.setStyleSheet("""
            QLineEdit {
                background-color: #222;
                color: white;
                border: 2px solid #00ffff;
                border-radius: 8px;
                padding: 5px;
                font-size: 14px;
            }
        """)

        self.file_button = QPushButton("Attach File", self)
        self.file_button.setGeometry(730, 270, 100, 30)
        self.file_button.clicked.connect(self.attach_file)
        self.file_button.setStyleSheet("""
            QPushButton {
                background-color: #ff5722;
                color: white;
                border-radius: 10px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #e64a19;
            }
        """)

        self.create_button("Open Image", self.open_image, 30, 340)
        self.create_button("Hide Message", self.hide_message, 180, 340)
        self.create_button("Show Message", self.show_message, 360, 340)
        self.create_button("Save Image", self.save_image, 540, 340)
        self.create_button("Clear", self.clear_all, 720, 340)

        self.create_button("Hide in File", self.hide_in_any_file, 30, 400)
        self.create_button("Reveal from File", self.reveal_from_any_file, 180, 400)

        self.status = QLabel("Ready", self)
        self.status.setGeometry(20, 570, 600, 20)
        self.status.setStyleSheet("color: white;")

    def create_button(self, text, func, x, y):
        btn = QPushButton(text, self)
        btn.setGeometry(x, y, 130, 40)
        btn.setStyleSheet("""
            QPushButton {
                background-color: #00bcd4;
                color: white;
                border-radius: 10px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0097a7;
            }
        """)
        btn.clicked.connect(func)

    def open_image(self):
        file, _ = QFileDialog.getOpenFileName(self, "Open Image", "", "Images (*.png *.jpg *.jpeg)")
        if file:
            self.open_file = file
            pixmap = QPixmap(file).scaled(self.image_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.image_label.setPixmap(pixmap)
            self.status.setText("Image loaded.")

    def attach_file(self):
        file, _ = QFileDialog.getOpenFileName(self, "Select File to Hide")
        if file:
            with open(file, "rb") as f:
                self.file_data = base64.b64encode(f.read()).decode()
                self.file_name = os.path.basename(file)
            self.status.setText(f"File '{self.file_name}' attached.")

    def generate_key(self, password):
        hashed = hashlib.sha256(password.encode()).digest()
        return base64.urlsafe_b64encode(hashed)

    def hide_message(self):
        if not self.open_file:
            QMessageBox.warning(self, "Error", "Please load an image first.")
            return

        message = self.text_box.toPlainText().strip()
        if not message and not self.file_data:
            QMessageBox.warning(self, "Error", "Nothing to hide.")
            return

        password = self.secret_key.text()
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a secret key.")
            return

        try:
            key = self.generate_key(password)
            fernet = Fernet(key)

            combined_msg = f"text::{message}"
            if self.file_data:
                combined_msg += f"||file::{self.file_name}:::{self.file_data}"

            encrypted_msg = fernet.encrypt(combined_msg.encode()).decode()
            self.hidden_image = lsb.hide(self.open_file, encrypted_msg)
            self.status.setText("Message hidden. Save the image.")
            QMessageBox.information(self, "Success", "Message and file hidden successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to hide message: {e}")

    def show_message(self):
        if not self.open_file:
            QMessageBox.warning(self, "Error", "Please load an image first.")
            return

        password = self.secret_key.text()
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a secret key.")
            return

        try:
            encrypted_msg = lsb.reveal(self.open_file)
            if not encrypted_msg:
                QMessageBox.information(self, "No Message", "No hidden message found.")
                return

            key = self.generate_key(password)
            fernet = Fernet(key)
            decrypted_msg = fernet.decrypt(encrypted_msg.encode()).decode()

            if "||file::" in decrypted_msg:
                text_part, file_part = decrypted_msg.split("||file::")
                self.text_box.setPlainText(text_part.replace("text::", ""))
                filename, file_data = file_part.split(":::")
                file_bytes = base64.b64decode(file_data)
                save_path, _ = QFileDialog.getSaveFileName(self, f"Save {filename}", filename)
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(file_bytes)
                    self.status.setText(f"Message and file '{filename}' extracted.")
                else:
                    self.status.setText("Message shown, file skipped.")
            else:
                self.text_box.setPlainText(decrypted_msg.replace("text::", ""))
                self.status.setText("Message revealed.")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to reveal message: {e}")

    def save_image(self):
        if self.hidden_image:
            path, _ = QFileDialog.getSaveFileName(self, "Save Image", "", "PNG Images (*.png)")
            if path:
                self.hidden_image.save(path)
                self.status.setText("Image saved.")
                QMessageBox.information(self, "Saved", f"Image saved to {path}")
        else:
            QMessageBox.warning(self, "Error", "No image to save.")

    def clear_all(self):
        self.text_box.clear()
        self.secret_key.clear()
        self.image_label.clear()
        self.open_file = None
        self.file_data = None
        self.file_name = None
        self.status.setText("Cleared all.")

    def hide_in_any_file(self):
        carrier_file, _ = QFileDialog.getOpenFileName(self, "Select Carrier File (any type)")
        if not carrier_file:
            return

        message = self.text_box.toPlainText().strip()
        if not message and not self.file_data:
            QMessageBox.warning(self, "Error", "Nothing to hide.")
            return

        password = self.secret_key.text()
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a secret key.")
            return

        try:
            key = self.generate_key(password)
            fernet = Fernet(key)

            combined_msg = f"text::{message}"
            if self.file_data:
                combined_msg += f"||file::{self.file_name}:::{self.file_data}"

            encrypted_payload = fernet.encrypt(combined_msg.encode())

            with open(carrier_file, "rb") as cf:
                carrier_data = cf.read()

            output_file, _ = QFileDialog.getSaveFileName(self, "Save Encrypted File", "output.steg")
            if output_file:
                with open(output_file, "wb") as out:
                    out.write(carrier_data)
                    out.write(b"\n--STEG--\n")
                    out.write(base64.b64encode(encrypted_payload))
                self.status.setText("Message hidden in file.")
                QMessageBox.information(self, "Success", f"Data hidden in {output_file}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to hide data: {e}")

    def reveal_from_any_file(self):
        steg_file, _ = QFileDialog.getOpenFileName(self, "Select File to Extract")
        if not steg_file:
            return

        password = self.secret_key.text()
        if not password:
            QMessageBox.warning(self, "Error", "Please enter a secret key.")
            return

        try:
            with open(steg_file, "rb") as f:
                content = f.read()

            if b"\n--STEG--\n" not in content:
                QMessageBox.warning(self, "Error", "No hidden data found.")
                return

            payload = content.split(b"\n--STEG--\n")[-1]
            encrypted_msg = base64.b64decode(payload)

            key = self.generate_key(password)
            fernet = Fernet(key)
            decrypted_msg = fernet.decrypt(encrypted_msg).decode()

            if "||file::" in decrypted_msg:
                text_part, file_part = decrypted_msg.split("||file::")
                self.text_box.setPlainText(text_part.replace("text::", ""))
                filename, file_data = file_part.split(":::")
                file_bytes = base64.b64decode(file_data)
                save_path, _ = QFileDialog.getSaveFileName(self, f"Save {filename}", filename)
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(file_bytes)
                    self.status.setText(f"Message and file '{filename}' extracted.")
                else:
                    self.status.setText("Message shown, file skipped.")
            else:
                self.text_box.setPlainText(decrypted_msg.replace("text::", ""))
                self.status.setText("Message revealed.")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to reveal message: {e}")

    def init_particles(self):
        for _ in range(30):
            particle = Particle(self)
            particle.show()
            self.particles.append(particle)

    def animate_particles(self):
        for p in self.particles:
            p.animate()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    win = SteganoApp()
    win.show()
    sys.exit(app.exec_())
