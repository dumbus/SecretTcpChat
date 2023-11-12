import socket
import random

from scapy.all import *

SERVER_IP = "192.168.56.1"
SERVER_PORT = 5000
CLIENT_IP = socket.gethostbyname(socket.gethostname())
CLIENT_PORT = random.randint(1024, 65535)

def client_main():
    print(f"[STARTED] Client {CLIENT_IP}:{CLIENT_PORT} started.")
    connect_to_server()


def connect_to_server():
    # Send SYN to a listening server
    ip = IP(src=CLIENT_IP, dst=SERVER_IP)
    syn = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=100)

    # Listen for the server's response (SYN/ACK)
    synack = sr1(ip/syn)

    # Send an acknowledgement from client for server's response (ACK)
    ack = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A", seq=synack.ack, ack=synack.seq + 1)
    send(ip/ack)

if __name__ == '__main__':
    client_main()