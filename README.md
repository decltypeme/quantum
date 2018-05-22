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

