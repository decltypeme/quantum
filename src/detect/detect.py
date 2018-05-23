#!/usr/bin/env python
import argparse
import re
from scapy.all import *
import signal
import sys
import base64

global total_detected_packets
all_hashed_packets = dict()

def _finish():
    print('User requested to close..')
    print('Total Detected Fake Packets: %d' %(total_detected_packets))
    sys.exit(0)

"""
Catches the Ctrl + C signal. Used to print out statstics at the end.
"""    
def safe_close(signal, frame):
	_finish()

signal.signal(signal.SIGINT, safe_close)


def _quantum_detect(packet):
	global total_detected_packets
	(header, payload) = encode_packet(packet)
	if(header in all_hashed_packets.keys()):
		#Headr already exists
		previous_payload = all_hashed_packets[header]
		if (previous_payload != payload):
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
			packet[TCP].sport,
			packet[IP].dst,
			packet[TCP].dport,
			packet[TCP].seq,
			packet[TCP].ack
			)
		payload = packet[TCP][Raw].load
		return (
			base64.b64encode(header_info),
			base64.b64encode(payload)
			)

if __name__ == "__main__":
	global total_detected_packets
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
	total_detected_packets = 0
	if(args.read != None):
		sniff(
			offline=args.read,
			filter=args.expression,
			lfilter=tcp_lambda_filter,
			prn=lambda packet: _quantum_detect(packet)
			)
		_finish()
	else:
		while(True):
			print("Listening on interface %s......" % (args.interface))
			#Read this magical number and then clear the dictionary
			sniff(
				count=4200,
				iface=args.interface,
				filter=args.expression,
				lfilter=tcp_lambda_filter,
				prn=lambda packet: _quantum_detect(packet)
				)
			all_hashed_packets.clear()