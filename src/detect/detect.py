#!/usr/bin/env python
import argparse
import re
from scapy.all import *
import signal
import sys
import base64

total_detected_packets = 0
all_hashed_packets = dict()

"""
Catches the Ctrl + C signal. Used to print out statstics at the end.
"""
def safe_close(signal, frame):
        print('User requested to close..')
        print('Total Detected Fake Packets: %d' %(total_detected_packets))
        sys.exit(0)

signal.signal(signal.SIGINT, safe_close)


def _quantum_detect(packet):
	(header, payload) = encode_packet(packet)
	if(header in all_hashed_packets.keys()):
		#Headr already exists
		previous_payload = all_hashed_packets[header]
		if (previous_payload == payload):
			# We have found an injected packet:
			print("Found an injected packet...\nOriginal:\t%s\nFake:\t%s") % (
				payload,
				previous_payload
				)
			total_detected_packets+=1
	else:
		#Add this header
		all_hashed_packets[header] = payload

#This functiomn maps a packet to a <header, payload>
#This can be used to determine if the packet has been seen before
#Throws Exception if packet is not TCP. Must be caught by the caller.
def encode_packet(packet):
		header_info = "Src: %s:%d, Dst: %s:%d, TCP: Seq:%d, Ack: %d" % (
			packet[IP].src,
			packet[IP].sport,
			packet[IP].dst.
			packet[IP].dport,
			packet[TCP].seq,
			packet[TCP].ack
			)
		payload = packet[TCP][Raw].load
		return (
			base64.b64encode(header_info).hexdigest(),
			base64.b64encode(payload).hexdigest()
			)



if __name__ == "__main__":	
	parser = argparse.ArgumentParser()
	arg_group = parser.add_mutually_exclusive_group()

	arg_group.add_argument("-r", "--read",
		help="Read packets from <file> (tcpdump format). Useful for detecting MotS attacks in existing network traces.")
	arg_group.add_argument("-i", "--interface", default="eth0",
		help="Listen on network device <interface> (e.g., eth0). Default is eth0.")
	parser.add_argument("-e", "--expression", default="tcp", 
		help="A berkeley packet filter describing the packets to be captured")
	#Parse the command line arguments
	args = parser.parse_args()
	#To make sure, we intercept TCP packets
	tcp_lambda_filter = lambda p: p.haslayer(IP) and p.haslayer(TCP) and p.haslayer(Raw)
	if(args.read):
		sniff(
			offline=args.file,
			filter=args.expression,
			lfilter=tcp_lambda_filter,
			prn=lambda packet: _quantum_detect(packet)
			)
	else:
		while(True):
			#Read this magical number and then clear the dictionary
			sniff(
				count=4200,
				iface=args.interface,
				filter=args.expression,
				lfilter=tcp_lambda_filter,
				prn=lambda packet: _quantum_detect(packet)
				)
			all_hashed_packets.clear()