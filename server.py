import random
from scapy.all import conf, get_if_addr, IP, TCP, send, sniff

SERVER_IP = get_if_addr(conf.iface)
SERVER_PORT = 5000
# INTERFACE = "" # prod version
INTERFACE = "\\Device\\NPF_Loopback" # for local testing

connected_clients = []

def server_main():
    print(f"[STARTED] Server started.")
    listen_for_connection()

def listen_for_connection():
    print(f"[LISTENING] Server is listening at: {SERVER_IP}:{SERVER_PORT}.")

    listening = True

    while listening:
        sniff(filter = f"tcp and port {SERVER_PORT}", prn=handle_connection, iface=INTERFACE) # for local testing
        # sniff(filter = f"tcp and port {SERVER_PORT}", prn=handle_connection) # prod version

def handle_connection(packet):
    if (packet[TCP].flags == "S"):
        dst = get_ip_from_payload(packet)
        ip = get_custom_ip_layer(dst)
        
        sport=SERVER_PORT
        dport = packet[TCP].sport
        seg_len = len(packet[TCP].payload)
        seq = packet[TCP].seq
        ack = seq + seg_len

        synack = TCP(sport=sport, dport=dport, flags="SA", seq=seq, ack=ack)
        send(ip/synack, verbose=0)
    
    elif (packet[TCP].flags == "A"):
        client_ip = get_ip_from_payload(packet)
        client_port = packet[TCP].sport

        connected_clients.append({'ip': client_ip, 'port': client_port})
        print(f"[NEW CONNECTION] New client connected: {client_ip}:{client_port}.")

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
    raw_text_data = bytes(packet[TCP].payload).decode('UTF8','replace')

    ip_pointer_index = raw_text_data.find("__")
    ip_address = raw_text_data[0:ip_pointer_index]

    return ip_address

if __name__ == '__main__':
    server_main()