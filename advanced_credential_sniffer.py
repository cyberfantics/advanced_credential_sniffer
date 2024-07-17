# -*- coding: utf-8 -*-
"""
Created on Wed Jul 17 18:50:10 2024

@author: Mansoor
"""

import re
import logging
import argparse
from base64 import b64decode
from scapy.all import *

# Initialize logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Regular expression for matching email addresses
email_regex = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'

# Lists to track awaiting logins and passwords for Telnet
awaiting_login = []
awaiting_password = []
unmatched = []

# Function to extract FTP credentials from packets
def extract_ftp(packet, output_file):
    try:
        payload = packet[Raw].load.decode("utf-8").rstrip()
        if payload[:4] == 'USER':
            msg = f"{packet[IP].dst} FTP Username: {payload[5:]}"
            logger.info(msg)
            output_file.write(msg + '\n')
        elif payload[:4] == 'PASS':
            msg = f"{packet[IP].dst} FTP Password: {payload[5:]}"
            logger.info(msg)
            output_file.write(msg + '\n')
    except Exception as e:
        logger.error(f"Error extracting FTP credentials: {e}")

# Function to extract SMTP credentials from packets
def extract_smtp(packet, output_file):
    try:
        payload = packet[Raw].load
        decoded = b64decode(payload).decode("utf-8")
        conn_data = (packet[IP].src, packet[TCP].sport)
        if re.search(email_regex, decoded):
            msg = f"{packet[IP].dst} SMTP Username: {decoded}"
            logger.info(msg)
            output_file.write(msg + '\n')
            unmatched.append(conn_data)
        elif conn_data in unmatched:
            msg = f"{packet[IP].dst} SMTP Password: {decoded}"
            logger.info(msg)
            output_file.write(msg + '\n')
            unmatched.remove(conn_data)
    except Exception as e:
        logger.error(f"Error extracting SMTP credentials: {e}")

# Function to extract Telnet credentials from packets
def extract_telnet(packet, output_file):
    try:
        payload = packet[Raw].load.decode("utf-8").rstrip()
    except:
        return

    conn_data = (packet[IP].src, packet[TCP].sport)  # Assume server is source
    if payload[:5] == "login":
        awaiting_login.append(conn_data)
        return
    elif payload[:8] == "Password":
        awaiting_password.append(conn_data)
        return

    conn_data = (packet[IP].dst, packet[TCP].dport)  # Assume client is source
    if conn_data in awaiting_login:
        msg = f"{packet[IP].dst} Telnet Username: {payload}"
        logger.info(msg)
        output_file.write(msg + '\n')
        awaiting_login.remove(conn_data)
    elif conn_data in awaiting_password:
        msg = f"{packet[IP].dst} Telnet Password: {payload}"
        logger.info(msg)
        output_file.write(msg + '\n')
        awaiting_password.remove(conn_data)

# Function to extract HTTP credentials or search for specific keywords in packets
def extract_http(packet, output_file, search_string=None):
    try:
        payload = packet[Raw].load.decode("utf-8")
        if search_string and search_string in payload:
            msg = f"{packet[IP].src} HTTP Keyword Found: {search_string} in {payload}"
            logger.info(msg)
            output_file.write(msg + '\n')
        if "Authorization" in payload:
            auth_info = payload.split("Authorization:")[1].split("\r\n")[0]
            msg = f"{packet[IP].src} HTTP Authorization: {auth_info}"
            logger.info(msg)
            output_file.write(msg + '\n')
    except Exception as e:
        logger.error(f"Error extracting HTTP data: {e}")

# Function to process packets and extract credentials or search keywords
def process_packets(pcap_file, output_file_path, search_string=None):
    packets = rdpcap(pcap_file)
    with open(output_file_path, 'w') as output_file:
        for packet in packets:
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                if packet[TCP].dport == 21:
                    extract_ftp(packet, output_file)
                elif packet[TCP].dport == 25:
                    extract_smtp(packet, output_file)
                elif packet[TCP].sport == 23 or packet[TCP].dport == 23:
                    extract_telnet(packet, output_file)
                elif packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    extract_http(packet, output_file, search_string)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract credentials from pcap file")
    parser.add_argument("pcap_file", help="Path to the pcap file to be processed")
    parser.add_argument("output_file", help="Path to the output file where results will be saved")
    parser.add_argument("--search", help="Optional string to search for in HTTP packets", default=None)
    
    args = parser.parse_args()
    
    process_packets(args.pcap_file, args.output_file, args.search)
