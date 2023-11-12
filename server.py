import socket

SERVER_IP = socket.gethostbyname(socket.gethostname())
SERVER_PORT = 5000

def server_main():
    print("Hello from server")

if __name__ == '__main__':
    server_main()