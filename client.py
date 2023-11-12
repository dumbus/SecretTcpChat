import random
import sys

from scapy.all import conf, get_if_addr, IP, TCP, sr, send

# SERVER_IP = "192.168.1.102" # prod version
SERVER_IP = get_if_addr(conf.iface) # dev version
SERVER_PORT = 5000
CLIENT_IP = get_if_addr(conf.iface)
CLIENT_PORT = random.randint(1024, 65535)

def client_main():
    print(f"[STARTED] Client {CLIENT_IP}:{CLIENT_PORT} started.")
    connect_to_server()


def connect_to_server():
    # Send SYN to a listening server
    ip = IP(src=CLIENT_IP, dst=SERVER_IP)
    syn = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=0)

    # Listen for the server's response (SYN/ACK)
    synack = sr(ip/syn, timeout=2)

    if (synack == None or synack[TCP].flags != 18):
        print("[ERROR] No connection with TCP server.")
        sys.exit()
    else:
        # Send an acknowledgement from client for server's response (ACK)
        ack = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A", seq=synack.ack, ack=synack.seq + 1)
        send(ip/ack)

if __name__ == '__main__':
    client_main()