import socket
import random

SERVER_IP = "192.168.56.1"
SERVER_PORT = 5000
CLIENT_IP = socket.gethostbyname(socket.gethostname())
CLIENT_PORT = random.randint(1024, 65535)

def client_main():
    print("Hello from client")

if __name__ == '__main__':
    client_main()