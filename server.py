import socket
from scapy.all import *

SERVER_IP = get_if_addr(conf.iface)
SERVER_PORT = 5000
# INTERFACE = ""
INTERFACE = "\\Device\\NPF_Loopback" # for local testing

def server_main():
    print(f"[STARTED] Server started.")
    listen_for_client()
    # custom_listen_to_client()

def listen_for_client():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(1)

    print(f"[LISTENING] Server is listening at: {SERVER_IP}:{SERVER_PORT}.")

    server_socket.accept()

def custom_listen_to_client():
    print(f"[LISTENING] Server is listening at: {SERVER_IP}:{SERVER_PORT}.")

    listening = True

    while listening:
        # sniff(filter = f"tcp and port {SERVER_PORT}", prn=lambda x: x.summary())
        sniff(filter = f"tcp and port {SERVER_PORT}", prn=handle_connection, iface=INTERFACE) # for local testing

def handle_connection(packet):
    if (packet[TCP].flags == "S"):
        src = SERVER_IP
        dst = packet[IP].src
        ip = IP(src=src, dst=dst)
        
        sport=SERVER_PORT
        dport = packet[TCP].sport
        seg_len = len(packet[TCP].payload)
        seq = packet[TCP].seq
        ack = seq + seg_len
        synack = TCP(sport=sport, dport=dport, flags="SA", seq=seq, ack=ack)

        send(ip/synack)
    

if __name__ == '__main__':
    server_main()