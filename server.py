import random
import time
import sys
from scapy.all import conf, get_if_addr, IP, TCP, send, sniff, Raw

SERVER_IP = get_if_addr(conf.iface)
SERVER_PORT = 5000
# INTERFACE = "" # prod version
INTERFACE = "\\Device\\NPF_Loopback" # for local testing
TIMEOUT = 3

# TODO: seq and ack numbers
# TODO: resend lost packets

connected_clients = []
disconnecting_clients = []

def server_main():
    print(f"[STARTED] Server started.")

    start_listening()

def start_listening():
    print(f"[LISTENING] Server is listening at: {SERVER_IP}:{SERVER_PORT}.")

    listening = True

    while listening:
        sniff(filter = f"tcp and dst port {SERVER_PORT} and dst host {SERVER_IP}", prn=handle_packets, iface=INTERFACE) # for local testing
        # sniff(filter = f"tcp and port {SERVER_PORT}", prn=handle_clients_data) # prod version

def handle_packets(packet):
    client_ip = get_ip_from_payload(packet)
    client_port = packet[TCP].sport
    client = {'ip': client_ip, 'port': client_port}

    if (client not in connected_clients):
        if (packet[TCP].flags == "S"):
            ip = get_custom_ip_layer(client_ip)

            seq_num = packet[TCP].seq # ???
            ack_num = seq_num + 1

            synack = TCP(sport=SERVER_PORT, dport=client_port, flags="SA", seq=seq_num, ack=ack_num)
            send(ip/synack, verbose=0)
        elif (packet[TCP].flags == "A"):
            time.sleep(0.1) # client need some time to start listening, so we are waitind
            connected_clients.append(client)
            print(f"[NEW CONNECTION] New client connected: {client_ip}:{client_port}.")

            ip = get_custom_ip_layer(client_ip)
            raw = Raw(f"[CONNECTED] Connected to server {SERVER_IP}:{SERVER_PORT}.")

            seg_len = len(packet[TCP].payload) # ???
            seq_num = packet[TCP].seq # ???
            ack_num = seq_num + seg_len # ???

            pshack = TCP(sport=SERVER_PORT, dport=client_port, flags="PA", seq=seq_num, ack=ack_num)
            send(ip/pshack/raw, iface=INTERFACE, verbose=0)

            broadcast_data_to_clients(f"Client {client_ip}:{client_port} connected to server!", client, False)

    if (client in connected_clients):
        if (packet[TCP].flags == "PA"):
            data = get_data_from_payload(packet)
            print(f"[DATA] Data from client: {client_ip}:{client_port} - {data}")

            ip = get_custom_ip_layer(client_ip)

            seg_len = len(packet[TCP].payload) # ???
            seq_num = packet[TCP].seq # ???
            ack_num = seq_num + seg_len # ???

            ack = TCP(sport=SERVER_PORT, dport=client_port, flags="A", seq=seq_num, ack=ack_num)
            send(ip/ack, iface=INTERFACE, verbose=0)

            broadcast_data_to_clients(data, client)
        
        if (packet[TCP].flags == "F"):
            ip = get_custom_ip_layer(client_ip)

            seg_len = len(packet[TCP].payload) # ???
            seq_num = packet[TCP].seq # ???
            ack_num = seq_num + seg_len # ???

            finack = TCP(sport=SERVER_PORT, dport=client_port, flags="A", seq=seq_num, ack=ack_num)
            send(ip/finack, verbose=0)

            time.sleep(0.1)

            ip = get_custom_ip_layer(client_ip)

            seg_len = len(packet[TCP].payload) # ???
            seq_num = packet[TCP].seq # ???
            ack_num = seq_num + seg_len # ???

            fin = TCP(sport=SERVER_PORT, dport=client_port, flags="F", seq=seq_num, ack=ack_num)
            send(ip/fin, verbose=0)

            disconnecting_clients.append(client)

        if (packet[TCP].flags == "A" and client in disconnecting_clients):
            connected_clients.remove(client)
            disconnecting_clients.remove(client)
            print(f"[DISCONNECTION] Client gracefully disconnected: {client_ip}:{client_port}.")
            broadcast_data_to_clients(f"Client {client_ip}:{client_port} disconnected from server!", client, False)

        if (packet[TCP].flags == "R"):
            connected_clients.remove(client)
            print(f"[TERMINATED] Client {client_ip}:{client_port} force terminated connection.")
            broadcast_data_to_clients(f"Client {client_ip}:{client_port} disconnected from server!", client, False)    

def broadcast_data_to_clients(data, sender_client, add_ip = True):
    if add_ip:
        data_to_send = f"<{sender_client['ip']}:{sender_client['port']}> - {data}"
    else:
        data_to_send = data

    for client in connected_clients:
        if sender_client != client:
            dst = client["ip"]

            sport = SERVER_PORT
            dport = client["port"]

            ip = get_custom_ip_layer(dst)
            raw = Raw(data_to_send)

            # seg_len = len(packet[TCP].payload) # ???
            seq_num = 0 # ???
            ack_num = 0 # ???

            pshack = TCP(sport=sport, dport=dport, flags="PA", seq=seq_num, ack=ack_num)
            send(ip/pshack/raw, verbose=0) # TODO: add ack handling (resending lost packets)

def abort_connection():
    print(f"[ABORTING] Force abortion of connection with all clients.")

    for client in connected_clients:
        client_ip = client["ip"]
        client_port = client["port"]
        ip = get_custom_ip_layer(client_ip)

        # seg_len = len(packet[TCP].payload) # ???
        seq_num = 0 # ???
        ack_num = 0 # ???

        rst = TCP(sport=SERVER_PORT, dport=client_port, flags="R", seq=seq_num, ack=ack_num)
        send(ip/rst, verbose=0)

    print(f"[ABORTED] Connections with all clients were terminated.")

def get_custom_ip_layer(dst):
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

def get_ip_from_payload(packet):
    text_data = bytes(packet[TCP].payload).decode('UTF8','replace')

    ip_pointer_index = text_data.find("__")
    ip_address = text_data[0:ip_pointer_index]

    return ip_address

def get_data_from_payload(packet):
    text_data = bytes(packet[TCP].payload).decode('UTF8','replace')

    data_start_index = text_data.find("__") + 2
    data = text_data[data_start_index:]

    return data

if __name__ == '__main__':
    try:
        server_main()
    finally:
        print("[INTERRUPTED] Program execution was interrupted")
        abort_connection()