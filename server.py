import socket
from scapy.all import sniff

SERVER_IP = socket.gethostbyname(socket.gethostname())
SERVER_PORT = 5000

def server_main():
    print(f"[STARTED] Server started.")
    # listen_for_client()
    custom_listen_to_client()

def listen_for_client():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(1)

    print(f"[LISTENING] Server is listening at: {SERVER_IP}:{SERVER_PORT}.")

    server_socket.accept()

# def custom_listen_to_client():
#     listening = True

#     while listening:
#         # sniff(filter = f"tcp and port {SERVER_PORT}")
#         sniff(filter = 'tcp', prn=lambda x: x.summary())


if __name__ == '__main__':
    server_main()