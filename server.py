import socket

SERVER_IP = socket.gethostbyname(socket.gethostname())
SERVER_PORT = 5000

def server_main():
    print(f"[STARTED] Server started.")
    listen_for_client()

def listen_for_client():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(1)

    print(f"[LISTENING] Server is listening at: {SERVER_IP}:{SERVER_PORT}.")

    while True:
        client, address = server_socket.accept()
        

if __name__ == '__main__':
    server_main()