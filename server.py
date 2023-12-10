import random
from scapy.all import conf, get_if_addr, IP, TCP, send, sniff, Raw, sr1

SERVER_IP = get_if_addr(conf.iface)
SERVER_PORT = 5000
# INTERFACE = "" # prod version
INTERFACE = "\\Device\\NPF_Loopback" # for local testing

# TODO: seq and ack numbers

connected_clients = []

def server_main():
    print(f"[STARTED] Server started.")

    start_listening()

def start_listening():
    print(f"[LISTENING] Server is listening at: {SERVER_IP}:{SERVER_PORT}.")

    listening = True

    while listening:
        sniff(filter = f"tcp and dst port {SERVER_PORT} and dst host {SERVER_IP}", prn=handle_packets, iface=INTERFACE) # for local testing
        # sniff(filter = f"tcp and port {SERVER_PORT}", prn=handle_clients_data) # prod version

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
            seq = 0 # ???
            ack = 0 # ???

            pshack = TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=ack)
            send(ip/pshack/raw, verbose=0) # TODO: add ack handling

def handle_packets(packet):
    client_ip = get_ip_from_payload(packet)
    client_port = packet[TCP].sport
    client = {'ip': client_ip, 'port': client_port}

    if (client not in connected_clients):
        if (packet[TCP].flags == "S"):
            dst = client_ip
            ip = get_custom_ip_layer(dst)
            
            sport = SERVER_PORT
            dport =client_port
            seg_len = len(packet[TCP].payload)
            seq = packet[TCP].seq
            ack = seq + seg_len

            synack = TCP(sport=sport, dport=dport, flags="SA", seq=seq, ack=ack)
            send(ip/synack, verbose=0)
        elif (packet[TCP].flags == "A"):
            connected_clients.append({'ip': client_ip, 'port': client_port})
            print(f"[NEW CONNECTION] New client connected: {client_ip}:{client_port}.")

            ip = get_custom_ip_layer(client_ip)
            raw = Raw("[CONNECTED] Connected to server")
            
            sport = SERVER_PORT
            dport = packet[TCP].sport
            seg_len = len(packet[TCP].payload)
            seq = packet[TCP].seq
            ack = seq + seg_len

            pshack = TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=ack)
            send(ip/pshack/raw, verbose=0)

            broadcast_data_to_clients(f"Client {client_ip}:{client_port} connected to server!", client, False)

    if (client in connected_clients):
        if (packet[TCP].flags == "PA"):
            data = get_data_from_payload(packet)
            print(f"[DATA] Data from client: {client_ip}:{client_port} - {data}")

            dst = client_ip
            ip = get_custom_ip_layer(dst)
            
            sport = SERVER_PORT
            dport = client_port
            seg_len = len(packet[TCP].payload)
            seq = packet[TCP].seq # ???
            ack = seq + seg_len # ???

            ack = TCP(sport=sport, dport=dport, flags="A", seq=seq, ack=ack)
            send(ip/ack, verbose=0)

            broadcast_data_to_clients(data, client)

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
    server_main()