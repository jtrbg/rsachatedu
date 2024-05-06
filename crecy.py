import socket
import threading
from communication import ClientHandler
from keymanager import get_public_key_from_pem
from keymanager import RSAKeyManager

def main():
    secure = False
    key_manager = RSAKeyManager(secure)
    host = input("Enter the server IP address: ")
    port = 12345
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    server_pem = client_socket.recv(4096)
    server_public_key = get_public_key_from_pem(server_pem)
    client_socket.sendall(key_manager.get_public_key_pem())

    handler = ClientHandler(client_socket, host, key_manager.private_key)
    receiver_thread = threading.Thread(target=handler.handle_client)
    sender_thread = threading.Thread(target=handler.send_messages, args=(server_public_key,))
    receiver_thread.start()
    sender_thread.start()

    receiver_thread.join()
    sender_thread.join()
    client_socket.close()

if __name__ == "__main__":
    main()
