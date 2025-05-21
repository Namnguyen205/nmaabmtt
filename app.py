from flask import Flask, render_template, request, send_file, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import uuid

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_aes_key(user_key):
    key = user_key.encode('utf-8')
    return pad(key, 16)[:16]  # AES-128 key chuẩn 16 bytes

@app.route('/', methods=['GET', 'POST'])
def index():
    download_link = None

    if request.method == 'POST':
        action = request.form['action']
        user_key = request.form['key']
        file = request.files['file']

        if not file or not user_key:
            return "Vui lòng nhập đủ file và mã khóa!"

        file_data = file.read()
        key = get_aes_key(user_key)
        cipher = AES.new(key, AES.MODE_ECB)

        try:
            if action == 'encrypt':
                processed_data = cipher.encrypt(pad(file_data, AES.block_size))
                output_filename = f'encrypted_{uuid.uuid4().hex}.txt'
            else:
                processed_data = unpad(cipher.decrypt(file_data), AES.block_size)
                output_filename = f'decrypted_{uuid.uuid4().hex}.txt'

            output_path = os.path.join(UPLOAD_FOLDER, output_filename)
            with open(output_path, 'wb') as f:
                f.write(processed_data)

            # Render lại với đường link tải về
            return render_template('index.html', download_link=output_filename)

        except ValueError:
            return "Giải mã thất bại. Sai mã khóa hoặc dữ liệu không hợp lệ!"

    return render_template('index.html')

@app.route('/download/<filename>')
def download(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    return send_file(file_path, as_attachment=True)
