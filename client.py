import random
import sys
from scapy.all import conf, get_if_addr, IP, TCP, send, Raw, sniff

# SERVER_IP = "192.168.1.102" # prod version
SERVER_IP = get_if_addr(conf.iface) # dev version
SERVER_PORT = 5000
CLIENT_IP = get_if_addr(conf.iface)
CLIENT_PORT = random.randint(1024, 65535)
# INTERFACE = "" # prod version
INTERFACE = "\\Device\\NPF_Loopback" # for local testing

def client_main():
    print(f"[STARTED] Client {CLIENT_IP}:{CLIENT_PORT} started.")
    connect_to_server()

def connect_to_server():
    # Send SYN to a listening server
    ip = get_custom_ip_layer()
    raw = get_custom_data_layer()
    syn = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=0)
    send(ip/syn/raw, verbose=0)

    # Listen for the server's response (SYN/ACK)
    synack = sniff(filter = f"tcp and port {SERVER_PORT}", iface=INTERFACE, count=1)[0] # for local testing
    #synack =  sniff(filter = f"tcp and port {SERVER_PORT}", count=1)[0] # prod version

    if (synack == None or synack[TCP].flags != "SA"):
        print("[ERROR] No connection with TCP server.")
        sys.exit()
    else:
        # Send an acknowledgement from client for server's response (ACK)
        ack = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A", seq=synack.ack, ack=synack.seq + 1)
        send(ip/ack/raw, verbose=0)

def get_custom_ip_layer(dst=SERVER_IP):
    ip_parts = []

    for i in range(4):
        if (i != 0):
            ip_part = random.randint(0, 255)
        else:
            ip_part = random.randint(1, 255)
        
        ip_parts.append(str(ip_part))

    spoofed_ip_address = '.'.join(ip_parts)
    custom_ip_layer = IP(src=spoofed_ip_address, dst=dst)

    return custom_ip_layer

def get_custom_data_layer(data=""):
    data_with_ip = f"{CLIENT_IP}__{data}"
    custom_data_layer = Raw(data_with_ip)

    return custom_data_layer

if __name__ == '__main__':
    client_main()