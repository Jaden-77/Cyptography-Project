from flask import Flask, render_template, request, send_file
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import base64

app = Flask(__name__)

# Generate RSA Key Pair
def generate_key_pair():
    if not os.path.exists('keys'):
        os.makedirs('keys')

    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open('keys/private_key.pem', 'wb') as private_key_file:
        private_key_file.write(private_key)
    
    with open('keys/public_key.pem', 'wb') as public_key_file:
        public_key_file.write(public_key)

# Encrypt the file
def encrypt_file(file_path, key_path, output_file_path, vigenere_key, caesar_shift):
    with open(key_path, 'rb') as key_file:
        key = RSA.import_key(key_file.read())

    symmetric_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(key)
    enc_symmetric_key = cipher_rsa.encrypt(symmetric_key)

    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX)
    with open(file_path, 'rb') as file:
        plaintext = file.read()
        ciphertext, tag = cipher_aes.encrypt_and_digest(pad(plaintext, AES.block_size))

    # Apply Caesar cipher to the Base64-encoded ciphertext
    base64_ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    caesar_ciphertext = caesar_encrypt(base64_ciphertext, caesar_shift)

    # Apply Vigenère cipher
    vigenere_ciphertext = vigenere_encrypt(caesar_ciphertext, vigenere_key)

    with open(output_file_path, 'wb') as encrypted_file:
        encrypted_file.write(enc_symmetric_key)
        encrypted_file.write(cipher_aes.nonce)
        encrypted_file.write(tag)
        encrypted_file.write(vigenere_ciphertext.encode('utf-8'))

# Decrypt the file
def decrypt_file(file_path, key_path, output_file_path, vigenere_key, caesar_shift):
    with open(key_path, 'rb') as key_file:
        key = RSA.import_key(key_file.read())

    with open(file_path, 'rb') as encrypted_file:
        enc_symmetric_key = encrypted_file.read(256)
        nonce = encrypted_file.read(16)
        tag = encrypted_file.read(16)
        vigenere_ciphertext = encrypted_file.read().decode('utf-8')

    cipher_rsa = PKCS1_OAEP.new(key)
    symmetric_key = cipher_rsa.decrypt(enc_symmetric_key)

    # Reverse the Vigenère cipher
    vigenere_decrypted = vigenere_decrypt(vigenere_ciphertext, vigenere_key)

    # Reverse the Caesar cipher
    caesar_decrypted = caesar_decrypt(vigenere_decrypted, caesar_shift)

    # Decode from Base64 and decrypt the file content with AES
    decoded_ciphertext = base64.b64decode(caesar_decrypted)
    cipher_aes = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
    decrypted_bytes = unpad(cipher_aes.decrypt_and_verify(decoded_ciphertext, tag), AES.block_size)

    with open(output_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_bytes)

# Caesar cipher functions
def caesar_encrypt(plaintext, shift):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - base + shift) % 26 + base)
            ciphertext += encrypted_char
        else:
            ciphertext += char
    return ciphertext

def caesar_decrypt(ciphertext, shift):
    return caesar_encrypt(ciphertext, -shift)

# Vigenère cipher functions
def vigenere_encrypt(plaintext, keyword):
    ciphertext = ""
    keyword_repeated = (keyword * (len(plaintext) // len(keyword) + 1))[:len(plaintext)]
    for p, k in zip(plaintext, keyword_repeated):
        if p.isalpha():
            base = ord('A') if p.isupper() else ord('a')
            encrypted_char = chr((ord(p) - base + ord(k) - ord('A')) % 26 + base)
            ciphertext += encrypted_char
        else:
            ciphertext += p
    return ciphertext

def vigenere_decrypt(ciphertext, keyword):
    return vigenere_encrypt(ciphertext, ''.join([chr((26 - (ord(k) - ord('A'))) % 26 + ord('A')) for k in keyword]))

# Flask routes
@app.route('/')
def index():
    return render_template('index.html')
@app.route('/process', methods=['POST'])
def process():
    operation = request.form['action']
    file = request.files['file']
    filename = 'uploaded_file' + os.path.splitext(file.filename)[-1]
    file_path = os.path.join('uploads', filename)
    file.save(file_path)

    vigenere_key = request.form['vigenere_key']
    caesar_shift = int(request.form['caesar_shift'])

    if operation == 'encrypt':
        output_filename = 'encrypted_file' + os.path.splitext(file.filename)[-1]
        output_file_path = os.path.join('uploads', output_filename)
        encrypt_file(file_path, 'keys/public_key.pem', output_file_path, vigenere_key, caesar_shift)
        file_type = 'encrypted'
    elif operation == 'decrypt':
        output_filename = 'decrypted_file' + os.path.splitext(file.filename)[-1]
        output_file_path = os.path.join('uploads', output_filename)
        decrypt_file(file_path, 'keys/private_key.pem', output_file_path, vigenere_key, caesar_shift)
        file_type = 'decrypted'
    return render_template('download.html', operation=operation, filename=output_filename, file_type=file_type)

@app.route('/download/<filename>')
def download(filename):
    return send_file(os.path.join('uploads', filename), as_attachment=True)

if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    generate_key_pair()
    app.run(debug=True)
