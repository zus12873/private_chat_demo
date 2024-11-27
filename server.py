# Server Code
import socket
import hashlib
import os
import threading
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

users = {}  # Store usernames and hashed passwords
otp = {}  # Store OTPs (One-Time Passwords)
online_users = {}  # Store online users and their sockets
user_messages = {}  # Store messages for offline users
lock = threading.Lock()

def generate_otp():
    return os.urandom(4).hex()  # Generate a random OTP of 4 bytes, represented in hexadecimal

def handle_client(client_socket, addr):
    try:
        username = None
        while True:
            request = client_socket.recv(1024).decode()
            if not request:
                break

            command, *args = request.split('|')

            if command == "register":
                # Step 1: Server generates OTP and sends it to the client for verification
                username, password_hash = args
                lock.acquire()
                if username in users:
                    response = "User already exists"
                else:
                    # otp[username] = (generate_otp(), time.time() + 120)  # Generate OTP for verification with 2-minute expiry
                    # response = f"OTP for verification: {otp[username]}"
                    
                    otp[username] = (generate_otp(), time.time() + 120)  # Generate OTP for verification with 2-minute expiry
                    with open(f"{username}_otp.txt", "w") as otp_file:
                        otp_file.write(f"OTP for verification: {otp[username][0]}")
                    response = "OTP for verification has been saved to a file."

                lock.release()
                client_socket.send(response.encode())

            elif command == "verify_register":
                # Step 2: Client sends back OTP for verification
                username, password_hash, user_otp = args
                lock.acquire()
                if username in otp and otp[username][0] == user_otp and otp[username][1] > time.time():
                    # Store username and password only after OTP verification
                    users[username] = password_hash
                    del otp[username]  # Remove OTP after successful verification
                    response = "Registration successful"
                else:
                    response = "OTP verification failed"
                lock.release()
                client_socket.send(response.encode())

            elif command == "request_login_otp":
                # Step 3: Generate and send OTP for login verification
                username = args[0]
                lock.acquire()
                if username in users:
                    # otp[username] = (generate_otp(), time.time() + 120)  # Generate OTP for login with 2-minute expiry
                    # response = f"OTP for login: {otp[username]}"
                    otp[username] = (generate_otp(), time.time() + 120)  # Generate OTP for verification with 2-minute expiry
                    with open(f"{username}_otp.txt", "w") as otp_file:
                        otp_file.write(f"OTP for verification: {otp[username][0]}")
                    response = "OTP for verification has been saved to a file."

                else:
                    response = "Username does not exist"
                lock.release()
                client_socket.send(response.encode())

            elif command == "login":
                username, password_hash, user_otp = args
                lock.acquire()
                if username in users and users[username] == password_hash and otp.get(username)[0] == user_otp and otp.get(username)[1] > time.time():
                    response = "Login successful"
                    online_users[username] = client_socket
                    del otp[username]  # Remove OTP after successful login
                else:
                    response = "Login failed"
                lock.release()
                client_socket.send(response.encode())

            elif command == "send_text":
                sender, recipient, encrypted_message = args
                encrypted_message_bytes = bytes.fromhex(encrypted_message)
                lock.acquire()
                if recipient not in user_messages:
                    user_messages[recipient] = []
                user_messages[recipient].append(f"Message from {sender}: ".encode() + encrypted_message_bytes)
                client_socket.send(f"Message stored for {recipient}".encode())
                lock.release()

            elif command == "received_messages":
                lock.acquire()
                if username in user_messages and user_messages[username]:
                    response = b"\n".join(user_messages[username])
                    del user_messages[username]
                else:
                    response = b"No new messages"
                lock.release()
                client_socket.send(response)

            elif command == "logout":
                lock.acquire()
                if username in online_users:
                    del online_users[username]
                lock.release()
                response = "Logged out successfully"
                client_socket.send(response.encode())
                break

    except Exception as e:
        print(f"Exception for {addr}: {e}")
    finally:
        client_socket.close()
        lock.acquire()
        if username and username in online_users:
            del online_users[username]
        lock.release()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('0.0.0.0', 9998))
server_socket.listen(5)

print("Server listening on port 9998")

try:
    while True:
        client_sock, address = server_socket.accept()
        print(f"Accepted connection from {address}")
        client_handler = threading.Thread(target=handle_client, args=(client_sock, address))
        client_handler.start()
finally:
    server_socket.close()
