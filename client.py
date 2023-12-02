import random
import threading
import sys
from scapy.all import conf, get_if_addr, IP, TCP, send, Raw, sniff, sr1

# SERVER_IP = "192.168.1.102" # prod version
SERVER_IP = get_if_addr(conf.iface) # dev version
SERVER_PORT = 5000
CLIENT_IP = get_if_addr(conf.iface)
CLIENT_PORT = random.randint(1024, 65535)
# INTERFACE = "" # prod version
INTERFACE = "\\Device\\NPF_Loopback" # for local testing

# TODO: seq and ack numbers

def client_main():
    print(f"[STARTED] Client {CLIENT_IP}:{CLIENT_PORT} started.")

    connect_to_server()

    server_data_thread = threading.Thread(target=listen_for_server_data)
    client_data_thread = threading.Thread(target=listen_for_client_data)

    server_data_thread.start()
    client_data_thread.start()

def connect_to_server():
    print(f"[CONNECTING] Connecting to server {SERVER_IP}:{SERVER_PORT}...")

    # Send SYN to a listening server
    ip = get_custom_ip_layer()
    raw = get_custom_data_layer()
    syn = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=0)
    send(ip/syn/raw, verbose=0)

    # Listen for the server's response (SYN/ACK)
    synack = sniff(filter = f"tcp and dst port {CLIENT_PORT} and dst host {CLIENT_IP}", iface=INTERFACE, count=1)[0] # for local testing
    #synack =  sniff(filter = f"tcp and port {SERVER_PORT}", count=1)[0] # prod version

    if (synack == None or synack[TCP].flags != "SA"):
        print("[ERROR] No connection with TCP server.")
        sys.exit()
    else:
        # Send an acknowledgement from client for server's response (ACK)
        ack = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A", seq=synack.ack, ack=synack.seq)
        send(ip/ack/raw, verbose=0)

def listen_for_server_data():
    listening = True

    while listening:
        sniff(filter = f"tcp and dst port {CLIENT_PORT} and dst host {CLIENT_IP}", prn=handle_server_data, iface=INTERFACE) # for local testing
        # sniff(filter = f"tcp and port {SERVER_PORT}", prn=handle_data) # prod version

        listening = False

def listen_for_client_data():
    message = input()

    while message.lower().strip() != '.exit':
        ip = get_custom_ip_layer()
        raw = get_custom_data_layer(message)

        # seg_len = len(packet[TCP].payload) # ???
        seq = 0 # ???
        ack = 0 # ???

        pshack = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="PA", seq=seq, ack=ack)
        server_ack = sr1(ip/pshack/raw, verbose=0) # TODO: add ack handling

        message = input()

def handle_server_data(packet):
    if (packet[TCP].flags == "PA"):
        data = get_data_from_payload(packet)
        print(f"[FROM SERVER]: {data}")

        ip = get_custom_ip_layer()
        raw = get_custom_data_layer()
        
        sport = CLIENT_PORT
        dport = SERVER_PORT
        seg_len = len(packet[TCP].payload)
        seq = packet[TCP].seq # ???
        ack = seq + seg_len # ???

        ack = TCP(sport=sport, dport=dport, flags="A", seq=seq, ack=ack)
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

def get_data_from_payload(packet):
    text_data = bytes(packet[TCP].payload).decode('UTF8','replace')

    return text_data

if __name__ == '__main__':
    client_main()