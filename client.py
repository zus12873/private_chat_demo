
# Client Code
import socket
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_message(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(key, ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext.decode(errors='replace')  # Use 'replace' to handle undecodable bytes more gracefully

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('127.0.0.1', 9998))

username = input("Enter username: ")
password = input("Enter password: ")
password_hash = hashlib.sha256(password.encode()).hexdigest()

operation = input("Enter operation (register/login): ")
if operation == "register":
    # Step 1: Register and receive OTP from the server
    client_socket.send(f"register|{username}|{password_hash}".encode())
    response = client_socket.recv(1024).decode()
    print(response)
    
    # Step 2: Verify OTP to complete registration
    if response.startswith("OTP for verification"):
        otp = input("Enter OTP received: ")
        client_socket.send(f"verify_register|{username}|{password_hash}|{otp}".encode())
        response = client_socket.recv(1024).decode()
        print(response)

elif operation == "login":
    # Step 1: Request OTP for login
    client_socket.send(f"request_login_otp|{username}".encode())
    response = client_socket.recv(1024).decode()
    print(response)

    # Step 2: Use OTP to login
    if response.startswith("OTP for verification"):
        otp = input("Enter OTP received: ")
        client_socket.send(f"login|{username}|{password_hash}|{otp}".encode())
        response = client_socket.recv(1024).decode()
        print(response)

        if response == "Login successful":
            raw_key=input("Enter key: ")
            key = hashlib.sha256(raw_key.encode()).digest()[:16]  # Derive AES key from password
            while True:
                action = input("Enter action (send/received_messages/logout): ")
                if action == "send":
                    recipient = input("Enter recipient username: ")
                    text = input("Enter text to send: ")
                    encrypted_message = encrypt_message(key, text)
                    client_socket.send(f"send_text|{username}|{recipient}|{encrypted_message.hex()}".encode())
                    response = client_socket.recv(1024).decode()
                    print(response)
                elif action == "received_messages":
                    client_socket.send(f"received_messages|{username}".encode())
                    response = client_socket.recv(4096)
                    if response != b"No new messages":
                        messages = response.split(b'\n')
                        for message in messages:
                            if message.startswith(b"Message from"):
                                sender, encrypted_msg = message.split(b': ', 1)
                                try:
                                    decrypted_msg = decrypt_message(key, encrypted_msg)
                                    print(f"{sender.decode()}: {decrypted_msg}")
                                except Exception as e:
                                    print(f"Error decrypting message: {e}")
                    else:
                        print(response.decode())
                elif action == "logout":
                    client_socket.send("logout".encode())
                    response = client_socket.recv(1024).decode()
                    print(response)
                    break

client_socket.close()
