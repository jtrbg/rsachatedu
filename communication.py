import threading
import select
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
import ast

class ClientHandler:
    """
    Handles client interactions for encrypted messaging, including receiving and sending messages.
    """
    def __init__(self, client_socket, addr, private_key):
        """
        Initializes the ClientHandler.
        :param client_socket: Socket object, the client socket.
        :param addr: Tuple, the client address.
        :param private_key: RSA private key for decrypting messages.
        """
        self.client_socket = client_socket
        self.addr = addr
        self.private_key = private_key
        self.message_ready = threading.Event()
        self.message_ready.set()

    def handle_client(self):
        """
        Continuously listens for incoming messages and decrypts them.
        """
        while True:
            ready_to_read, _, _ = select.select([self.client_socket], [], [], None)
            if ready_to_read:
                message = self.client_socket.recv(4096)
                if message:
                    decrypted_message = ""
                    if self.private_key.key_size < 2048:
                        message_int = int.from_bytes(message, 'big')
                        plaintext_int = pow(message_int, self.private_key.private_numbers().d,self.private_key.private_numbers().n)
                        plaintext_bytes = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, byteorder='big')
                        decrypted_message = plaintext_bytes.decode('utf-8')
                        print("\r\033[K", end='')
                        print(f"{self.addr}: {decrypted_message}")
                    else:
                        decrypted_message = self.private_key.decrypt(
                            message, 
                            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                        )
                        print("\r\033[K", end='')
                        print(f"{self.addr}: {decrypted_message.decode()}")
                    self.message_ready.set()

    def send_messages(self, other_public_key):
        """
        Prompts the user for messages to send and encrypts them before sending.
        :param other_public_key: RSA public key of the receiver for encrypting messages.
        """
        while True:
            self.message_ready.wait()
            message_to_send = input("You: ")
            if message_to_send == '\\exit':
                self.client_socket.sendall(message_to_send.encode())
                break
            encrypted_message = ""
            if other_public_key.key_size < 2048:
                message_int = int.from_bytes(message_to_send.encode('utf-8'), byteorder='big')
                encrypted_message_int = pow(message_int, other_public_key.public_numbers().e,other_public_key.public_numbers().n)
                byte_size = (encrypted_message_int.bit_length()+ 7) // 8
                encrypted_message = encrypted_message_int.to_bytes(byte_size,byteorder='big')
            else:
                encrypted_message = other_public_key.encrypt(
                    message_to_send.encode(),
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
            self.client_socket.sendall(encrypted_message)
            print("Message sent, waiting for reply...", end = '')
            self.message_ready.clear()
