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

# TODO: create function to generate correct random IPs
random_ip_addresses = ["210.181.2.14", "200.3.48.237", "230.38.116.75", "177.241.188.245", "136.119.151.17", "154.177.246.190", "252.213.126.122", "85.106.73.28", "115.40.74.18", "236.53.173.79", "109.15.97.23", "6.82.78.24", "6.1.226.159", "204.24.207.127", "44.181.52.192", "31.201.82.101", "229.65.126.232", "137.204.211.126", "175.33.19.207", "210.107.161.191"]

def client_main():
    print(f"[STARTED] Client {CLIENT_IP}:{CLIENT_PORT} started.")
    connect_to_server()

def connect_to_server():
    # Send SYN to a listening server
    ip = get_spoofed_ip_layer()
    raw = get_raw_data_with_ip()
    syn = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=0)
    send(ip/syn/raw)

    # Listen for the server's response (SYN/ACK)
    synack = sniff(filter = f"tcp and port {SERVER_PORT}", iface=INTERFACE, count=1)[0] # for local testing
    #synack =  sniff(filter = f"tcp and port {SERVER_PORT}", count=1)[0] # prod version

    if (synack == None or synack[TCP].flags != 18):
        print("[ERROR] No connection with TCP server.")
        sys.exit()
    else:
        # Send an acknowledgement from client for server's response (ACK)
        ack = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A", seq=synack.ack, ack=synack.seq + 1)
        send(ip/ack/raw)

def get_spoofed_ip_layer(dst=SERVER_IP):
    index = random.randint(0, len(random_ip_addresses) - 1)
    spoofed_ip_address = random_ip_addresses[index]

    spoofed_ip_layer = IP(src=spoofed_ip_address, dst=dst)

    return spoofed_ip_layer

def get_raw_data_with_ip(data=""):
    data_with_ip = f"{CLIENT_IP}__{data}"
    raw_data_with_ip = Raw(data_with_ip)

    return raw_data_with_ip

if __name__ == '__main__':
    client_main()