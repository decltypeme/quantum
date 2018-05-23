# quantum
A project for injecting content in unencrypted TCP traffic and also detecting injected content


## quantum-inject

This module detects packets filtered out using a given filter and injects a pre-specified payload as a response.

### How to use

```
usage: inject.py [-h] [-i INTERFACE] [-r REGEXP] [-d DATAFILE] [-e EXPRESSION]

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Target Network interface to intercept traffic
  -r REGEXP, --regexp REGEXP
                        A regular expression to filter out packets
  -d DATAFILE, --datafile DATAFILE
                        The fake payload to be injected as response
  -e EXPRESSION, --expression EXPRESSION
                        A berkeley packet filter describing the packets to be
                        captured

```

Example:
```
./src/inject/inject.py -i eth0 -r "HTTP" -d data/examples/payload.data -e "tcp"
```

### How to run in VirtualBox

1. Select the network adapter as Birdged Adapter.
2. Allow the Promiscuous mode.
3. Run from the virtual machine.

## quantum-detect

This module detects injected fake payload from a packet capture file.

### How to use
```
usage: detect.py [-h] [-r READ | -i INTERFACE] [-e EXPRESSION]

optional arguments:
  -h, --help            show this help message and exit
  -r READ, --read READ  Read packets from <file> (tcpdump format). Useful for
                        detecting MotS attacks in existing network traces.
  -i INTERFACE, --interface INTERFACE
                        Listen on network device <interface> (e.g., eth0).
                        Default is eth0.
  -e EXPRESSION, --expression EXPRESSION
                        A berkeley packet filter describing the packets to be
                        captured

```

How to get an example pcap:
1. Run this in scapy
```
x = sniff(filter="tcp", count=5000, iface="eth0")
```
2. Run the inject on tcp traffic
3. Save the extracted packets
```
wrpcap("sample.cap", x)
```
4. Then run the quantum-detect:
```
./src/detect/detect.py -r sample.cap 
```

### How it works
It hasesh the header and payload of TCP packets in a dictionary. For every sniffed packet, the header is compared.

If the header is there and the payload is different, then there is an injection that has happened.

If the header is there and same payload, we don't signal an injection. Probably, this is a retransmission.

If the header is new, we store this packet for future search.