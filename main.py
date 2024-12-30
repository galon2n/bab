import flet as ft
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

def encrypt_file(file_path, password):
    """Encrypt a file using AES."""
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CFB(b"1234567890123456"), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, "rb") as f:
        data = f.read()

    encrypted_data = encryptor.update(data) + encryptor.finalize()
    encrypted_file_path = file_path + ".enc"

    with open(encrypted_file_path, "wb") as f:
        f.write(salt + encrypted_data)

    return encrypted_file_path


def decrypt_file(file_path, password):
    """Decrypt a file using AES."""
    with open(file_path, "rb") as f:
        data = f.read()

    salt = data[:16]
    encrypted_data = data[16:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CFB(b"1234567890123456"), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    decrypted_file_path = file_path.replace(".enc", ".decrypted.pdf")

    with open(decrypted_file_path, "wb") as f:
        f.write(decrypted_data)

    return decrypted_file_path


def get_all_pdfs(directory):
    """Get a list of all PDF files in the specified directory."""
    pdf_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".pdf"):
                pdf_files.append(os.path.join(root, file))
    return pdf_files


def main(page: ft.Page):
    page.title = "black-sup"
    page.window_width = 400
    page.window_height = 400

    def encrypt_clicked(e):
        if not password_field.value:
            output.value = "Password is required!"
        else:
            pdf_files = get_all_pdfs("/storage/emulated/0/")  # Example path, adjust based on your device
            if pdf_files:
                encrypted_files = []
                for pdf in pdf_files:
                    encrypted_file = encrypt_file(pdf, password_field.value)
                    encrypted_files.append(encrypted_file)
                output.value = f"Encrypted {len(encrypted_files)} files."
            else:
                output.value = "No PDF files found."
        page.update()

    def decrypt_clicked(e):
        if not password_field.value:
            output.value = "Password is required!"
        else:
            pdf_files = get_all_pdfs("/storage/emulated/0/")  # Example path, adjust based on your device
            if pdf_files:
                decrypted_files = []
                for pdf in pdf_files:
                    decrypted_file = decrypt_file(pdf, password_field.value)
                    decrypted_files.append(decrypted_file)
                output.value = f"Decrypted {len(decrypted_files)} files."
            else:
                output.value = "No PDF files found."
        page.update()

    password_field = ft.TextField(label="Password", password=True, width=300)
    encrypt_button = ft.ElevatedButton(text="Encrypt All", on_click=encrypt_clicked)
    decrypt_button = ft.ElevatedButton(text="Decrypt All", on_click=decrypt_clicked)
    output = ft.Text(value="", color="green")

    page.add(
        ft.Column(
            [
                ft.Text("Black*sup", style="headlineMedium"),
                password_field,
                ft.Row([encrypt_button, decrypt_button], alignment="center"),
                output,
            ],
            alignment="center",
        )
    )


if __name__ == "__main__":
    ft.app(target=main)
