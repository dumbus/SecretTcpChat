import random
import time
import sys
import threading
from scapy.all import conf, get_if_addr, IP, TCP, send, sniff, Raw

SERVER_IP = get_if_addr(conf.iface)
SERVER_PORT = 5000
TIMEOUT = 3

RUN_MODE = "dev"
SYSTEM_MODE = "win"
INTERFACE = ""
DEV_INTERFACE_WIN = "\\Device\\NPF_Loopback" # for local testing on Windows machine
DEV_INTERFACE_UNIX = "lo" # for local testing on Linux machine

# TODO: seq and ack numbers
# TODO: resend lost packets

connected_clients = []
disconnecting_clients = []

def server_main():
    print(f"[STARTED] Server started.")

    server_thread = threading.Thread(target=start_listening, daemon=True)
    stop_thread = threading.Thread(target=handle_stop, daemon=True)

    server_thread.start()
    stop_thread.start()

def start_listening():
    print(f"[LISTENING] Server is listening at: {SERVER_IP}:{SERVER_PORT}.")

    listening = True

    while listening:
        if (RUN_MODE == 'dev'):
            sniff(filter = f"tcp and dst port {SERVER_PORT} and dst host {SERVER_IP}", prn=handle_packets, iface=INTERFACE)
        elif (RUN_MODE == 'prod'):
            sniff(filter = f"tcp and dst port {SERVER_PORT} and dst host {SERVER_IP}", prn=handle_packets)

def handle_stop():
    listening = True

    while listening:
        try:
            input()
        except Exception:
            sys.exit()

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
            send(ip/pshack/raw, verbose=0)

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
            send(ip/ack, verbose=0)

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

def abort_connections():
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

def get_run_mode():
    global RUN_MODE
    cli_args = sys.argv

    if (len(cli_args) != 1):
        mode = str(sys.argv[1]).lower().strip()

        if (mode == 'prod'):
            RUN_MODE = 'prod'
            return
    
    RUN_MODE = 'dev'

def get_system_mode():
    global INTERFACE
    global SYSTEM_MODE
    cli_args = sys.argv

    if (len(cli_args) != 1):
        system = str(sys.argv[2]).lower().strip()

        if (system == 'unix'):
            SYSTEM_MODE = 'unix'
            INTERFACE = DEV_INTERFACE_UNIX
            return
        elif (system == 'win'):
            SYSTEM_MODE = 'win'
            INTERFACE = DEV_INTERFACE_WIN
            return
    
    SYSTEM_MODE = 'win'
    INTERFACE = DEV_INTERFACE_WIN

if __name__ == '__main__':
    get_run_mode()
    get_system_mode()
    print(f"Program was started in {RUN_MODE} mode for {SYSTEM_MODE} system.")

    server_main()

    try:
        while True:
            pass
    finally:
        print("[INTERRUPTED] Program execution was interrupted")

        if (len(connected_clients) > 0):
            abort_connections()

        sys.exit()