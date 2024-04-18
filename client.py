import random
import threading
import sys
import os
import time
from scapy.all import conf, get_if_addr, IP, TCP, send, Raw, sniff

RUN_MODE = "dev"
SYSTEM_MODE = "win"
TIMEOUT = 3

SERVER_IP = ""
SERVER_PORT = 5000

CLIENT_INTERFACE = ""
CLIENT_IP = ""
CLIENT_PORT = random.randint(1024, 65535)

DEV_INTERFACE_WIN = "\\Device\\NPF_Loopback" # for local testing on Windows machine
DEV_INTERFACE_UNIX = "lo" # for local testing on Linux machine

# TODO: seq and ack numbers
# TODO: resend lost packets

connected = False
disconnecting = False

def client_main():
    print(f"[STARTED] Client {CLIENT_IP}:{CLIENT_PORT} started.")

    connect_to_server()

    server_data_thread = threading.Thread(target=listen_for_server_data, daemon=True)
    client_data_thread = threading.Thread(target=listen_for_client_data, daemon=True)

    server_data_thread.start()
    client_data_thread.start()

def connect_to_server():
    print(f"[CONNECTING] Connecting to server {SERVER_IP}:{SERVER_PORT}...")

    ip = get_custom_ip_layer()
    raw = get_custom_data_layer()

    seq_num = 0 # ???

    syn = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="S", seq=seq_num)
    send(ip/syn/raw, verbose=0)

    sniff_result = sniff(filter = f"tcp and dst port {CLIENT_PORT} and dst host {CLIENT_IP}", count=1, timeout=TIMEOUT, iface=CLIENT_INTERFACE)

    try:
        synack = sniff_result[0]
    except IndexError:
        print("[ERROR] No connection with TCP server.")
        sys.exit()

    if (synack[TCP].flags != "SA"):
        print("[ERROR] No connection with TCP server.")
        sys.exit()
    else:
        ip = get_custom_ip_layer()
        raw = get_custom_data_layer()

        seq_num = synack[TCP].seq
        ack_num = synack[TCP].ack

        ack = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A", seq=seq_num, ack=ack_num)
        send(ip/ack/raw, verbose=0)

    global connected
    connected = True

def disconnect_from_server():
    print(f"[DISCONNECTING] Disconnecting from server {SERVER_IP}:{SERVER_PORT}...")

    ip = get_custom_ip_layer()
    raw = get_custom_data_layer()

    # seg_len = len(packet[TCP].payload) # ???
    seq_num = 0 # ???
    ack_num = 0 # ???

    fin = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="F", seq=seq_num, ack=ack_num)
    send(ip/fin/raw, verbose=0)

    global disconnecting
    disconnecting = True

    time.sleep(TIMEOUT * 2)

    print("[ERROR] No response from TCP server, aborting!")
    os._exit(1)

def abort_connection():
    print(f"[ABORTING] Force abortion of connection to server {SERVER_IP}:{SERVER_PORT}.")

    ip = get_custom_ip_layer()
    raw = get_custom_data_layer()

    # seg_len = len(packet[TCP].payload) # ???
    seq_num = 0 # ???
    ack_num = 0 # ???

    rst = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="R", seq=seq_num, ack=ack_num)
    send(ip/rst/raw, verbose=0)

    print(f"[ABORTED] Connection to server {SERVER_IP}:{SERVER_PORT} was aborted.")

def listen_for_server_data():
    listening = True

    while listening:
        sniff(filter = f"tcp and dst port {CLIENT_PORT} and dst host {CLIENT_IP}", prn=handle_server_data, iface=CLIENT_INTERFACE)

def listen_for_client_data():
    listening = True

    while listening:
        try:
            message = input()
        except Exception:
            sys.exit()

        if message.lower().strip() != '.exit':
            ip = get_custom_ip_layer()
            raw = get_custom_data_layer(message)

            # seg_len = len(packet[TCP].payload) # ???
            seq_num = 0 # ???
            ack_num = 0 # ???

            pshack = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="PA", seq=seq_num, ack=ack_num)
            send(ip/pshack/raw, verbose=0) # TODO: add ack handling (resending lost packets)
        else:
            disconnect_from_server()
            listening = False

def handle_server_data(packet):
    if (packet[TCP].flags == "PA" and disconnecting == False):
        data = get_data_from_payload(packet)
        print(data)

        ip = get_custom_ip_layer()
        raw = get_custom_data_layer()

        # seg_len = len(packet[TCP].payload) # ???
        seq_num = 0 # ???
        ack_num = 0 # ???

        ack_response = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A", seq=seq_num, ack=ack_num)
        send(ip/ack_response/raw, verbose=0)

    if (packet[TCP].flags == "A" and disconnecting == True):
        pass

    if (packet[TCP].flags == "F" and disconnecting == True):
        ip = get_custom_ip_layer()
        raw = get_custom_data_layer()

        # seg_len = len(packet[TCP].payload) # ???
        seq_num = 0 # ???
        ack_num = 0 # ???

        ack = TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A", seq=seq_num, ack=ack_num)
        send(ip/ack/raw, verbose=0)

        print(f"[DISCONNECTED] Disconnected from server {SERVER_IP}:{SERVER_PORT}...")
        os._exit(1)

    if (packet[TCP].flags == "R"):
        print(f"[TERMINATED] Server {SERVER_IP}:{SERVER_PORT} terminated connection")
        os._exit(1)

def get_custom_ip_layer():
    ip_parts = []

    for i in range(4):
        if (i != 0):
            ip_part = random.randint(0, 255)
        else:
            ip_part = random.randint(1, 255)
        
        ip_parts.append(str(ip_part))

    spoofed_ip_address = '.'.join(ip_parts)
    custom_ip_layer = IP(src=spoofed_ip_address, dst=SERVER_IP)

    return custom_ip_layer

def get_custom_data_layer(data=""):
    data_with_ip = f"{CLIENT_IP}__{data}"
    custom_data_layer = Raw(data_with_ip)

    return custom_data_layer

def get_data_from_payload(packet):
    text_data = bytes(packet[TCP].payload).decode('UTF8','replace')

    return text_data

def get_run_mode():
    global RUN_MODE
    cli_args = sys.argv

    if (len(cli_args) != 1):
        mode = str(sys.argv[1]).lower().strip()

        if (mode == 'prod'):
            RUN_MODE = 'prod'
        elif (mode == 'dev'):
            RUN_MODE = 'dev'

def get_system_mode():
    global SYSTEM_MODE
    cli_args = sys.argv

    if (len(cli_args) != 1):
        system = str(sys.argv[2]).lower().strip()

        if (system == 'unix'):
            SYSTEM_MODE = 'unix'
        elif (system == 'win'):
            SYSTEM_MODE = 'win'

def get_interface():
    global CLIENT_INTERFACE

    if (RUN_MODE == 'dev'):
        if (SYSTEM_MODE == 'win'):
            CLIENT_INTERFACE = DEV_INTERFACE_WIN
        if (SYSTEM_MODE == 'unix'):
            CLIENT_INTERFACE = DEV_INTERFACE_UNIX
    else:
        CLIENT_INTERFACE = conf.iface

def get_client_ip():
    global CLIENT_IP
    CLIENT_IP = get_if_addr(CLIENT_INTERFACE)

def get_server_ip():
    global SERVER_IP

    try:
        user_input = input("Enter ip of server you want to connect: ")
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Program execution was interrupted")
        sys.exit()

    ip = user_input.strip()
    ip_parts = ip.strip().split(".")

    if (len(ip_parts) != 4):
        print("[ERROR] You provided invalid ip address (ip address should have 4 parts divided by points), try again!")
        get_server_ip()
    
    i = 0

    for part in ip_parts:
        try:
            int_part = int(part)
        except ValueError:
            print("[ERROR] You provided invalid ip address (ip address should contain only integers divided by points), try again!")
            get_server_ip()
        
        if (i == 0):
            if (int_part <= 0 or int_part > 255):
                print("[ERROR] You provided invalid ip address (first part of ip address can not be equal to 0), try again !")
                get_server_ip()
        else:
            if (int_part < 0 or int_part > 255):
                print("[ERROR] You provided invalid ip address (ip address parts should be integers [0, 255]), try again!")
                get_server_ip()

        i += 1

    SERVER_IP = ip

def get_config():
    get_run_mode()
    get_system_mode()
    get_interface()
    get_client_ip()

    if (RUN_MODE == 'prod'):
        get_server_ip()

if __name__ == '__main__':
    get_config()

    print(f"[CONFIG] Program was started in {RUN_MODE} mode for {SYSTEM_MODE} system.")
    print(f"[CONFIG] Client is sending data via {CLIENT_INTERFACE} interface")

    client_main()

    try:
        while True:
            pass
    finally:
        print("[INTERRUPTED] Program execution was interrupted")

        if (connected == True):
            abort_connection()
        
        sys.exit()