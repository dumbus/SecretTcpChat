import random
from scapy.all import conf, get_if_addr, IP, TCP, send, sniff

SERVER_IP = get_if_addr(conf.iface)
SERVER_PORT = 5000
# INTERFACE = ""
INTERFACE = "\\Device\\NPF_Loopback" # for local testing

# TODO: create function to generate correct random IPs
random_ip_addresses = ["210.181.2.14", "200.3.48.237", "230.38.116.75", "177.241.188.245", "136.119.151.17", "154.177.246.190", "252.213.126.122", "85.106.73.28", "115.40.74.18", "236.53.173.79", "109.15.97.23", "6.82.78.24", "6.1.226.159", "204.24.207.127", "44.181.52.192", "31.201.82.101", "229.65.126.232", "137.204.211.126", "175.33.19.207", "210.107.161.191"]

def server_main():
    print(f"[STARTED] Server started.")
    custom_listen_to_client()

def custom_listen_to_client():
    print(f"[LISTENING] Server is listening at: {SERVER_IP}:{SERVER_PORT}.")

    listening = True

    while listening:
        # sniff(filter = f"tcp and port {SERVER_PORT}", prn=handle_connection)
        sniff(filter = f"tcp and port {SERVER_PORT}", prn=handle_connection, iface=INTERFACE) # for local testing

def handle_connection(packet):
    if (packet[TCP].flags == "S"):
        dst = get_ip_from_payload(packet)
        ip = get_spoofed_ip_layer(dst)
        
        sport=SERVER_PORT
        dport = packet[TCP].sport
        seg_len = len(packet[TCP].payload)
        seq = packet[TCP].seq
        ack = seq + seg_len
        synack = TCP(sport=sport, dport=dport, flags="SA", seq=seq, ack=ack)

        send(ip/synack, verbose=0)

def get_spoofed_ip_layer(dst):
    index = random.randint(0, len(random_ip_addresses) - 1)
    spoofed_ip_address = random_ip_addresses[index]

    spoofed_ip_layer = IP(src=spoofed_ip_address, dst=dst)

    return spoofed_ip_layer

def get_ip_from_payload(packet):
    raw_text_data = bytes(packet[TCP].payload).decode('UTF8','replace')

    ip_pointer_index = raw_text_data.find("__")
    ip_address = raw_text_data[0:ip_pointer_index]

    return ip_address

if __name__ == '__main__':
    server_main()