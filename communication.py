import threading
import select
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

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
            encrypted_message = other_public_key.encrypt(
                message_to_send.encode(),
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            self.client_socket.sendall(encrypted_message)
            print("Message sent, waiting for reply...", end = '')
            self.message_ready.clear()