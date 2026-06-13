from flask import Flask, render_template, request, send_file
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import os

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt_file():
    file = request.files["file"]
    password = request.form["password"]

    if not file or not password:
        return "File and password required!"

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    salt = os.urandom(16)
    key = generate_key(password, salt)

    fernet = Fernet(key)

    with open(filepath, "rb") as f:
        data = f.read()

    encrypted_data = fernet.encrypt(data)

    encrypted_path = filepath + ".enc"

    with open(encrypted_path, "wb") as f:
        f.write(salt + encrypted_data)

    return send_file(
        encrypted_path,
        as_attachment=True,
        download_name=file.filename + ".enc"
    )

if __name__ == "__main__":
    app.run(debug=True)
