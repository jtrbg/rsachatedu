import socket
import threading
from communication import ClientHandler
from keymanager import get_public_key_from_pem
from keymanager import RSAKeyManager

def main():
    secure = False
    key_manager = RSAKeyManager(secure)
    host = '0.0.0.0'
    port = 12345
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print("Server ready for connections...")
    client_socket, addr = server_socket.accept()
    print("Connected to:", addr)

    # Send the server's public key and receive the client's public key
    client_socket.sendall(key_manager.get_public_key_pem())
    client_pem = client_socket.recv(4096)
    client_public_key = get_public_key_from_pem(client_pem)

    # Initialize and start threads for handling client communications
    handler = ClientHandler(client_socket, addr[0], key_manager.private_key)
    receiver_thread = threading.Thread(target=handler.handle_client)
    sender_thread = threading.Thread(target=handler.send_messages, args=(client_public_key,))
    receiver_thread.start()
    sender_thread.start()

    receiver_thread.join()
    sender_thread.join()
    client_socket.close()
    server_socket.close()

if __name__ == "__main__":
    main()
