
#!/usr/bin/env python

""" 
Script to test whether a target webserver has the tcp_tw_recycle
option enabled.

Python requests is first used to make a HEAD request to the target webserver.
The "Connection: Close" header is set to ensure that the server ends up
in the TIME-WAIT state. 

If the HEAD request completes, Scapy is used to send a crafted SYN packet to the
same destination IP/port with a  user defined Timestamp value (100 by default).
Lack of SYN/ACK response would indicate that the server has dropped the second
connection attempt and may have tcp_tw_recycle enabled.
"""

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import random
import requests
import time
import sys
import argparse

__author__ = "MacroPolo"
__license__ = "MIT"
__version__ = "1.0.0"
__maintainer__ = "MacroPolo"
__email__ = "contact@slashtwentyfour.net"
__status__ = "Production"

parser = argparse.ArgumentParser(description="Detect linux servers with \
                                              tcp_tw_recycle enabled")

parser.add_argument("-d", "--domain", help="Target domain", action="store",
                    required=True)
parser.add_argument("-s", "--source-ip", help="Source IP address", 
                    action="store", required=True)
parser.add_argument("-p", "--dst-port", help="Destination port", action="store",
                    default=80)
parser.add_argument("-t", "--tsval", help="Crafted timestamp value", 
                    action="store", default=100)

# Display command help if no arguements are specified
if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()

domain = args.domain
src_ip = args.source_ip
src_port = random.randint(49152,65535)
dst_port = int(args.dst_port)
seq = random.getrandbits(32)
ts_val = int(args.tsval)

if dst_port == 80:
    proto = 'http://'
elif dst_port == 443:
    proto = 'https://'
else:
    proto = 'http://'

# Send a normal HEAD request with timestamp set using Requests
# Connection header is set to "close" to ensure that the server ends up in 
# TIME-WAIT state

print "---------------------------------------------"
print "Testing: %s" % (proto+domain)
print "---------------------------------------------"

try:
    print "--[STAGE 1]--"
    print "Sending HEAD request to server through OS TCP/IP Stack"
    r = requests.head((proto+domain), headers={"Connection":"close"}, 
                      timeout=5, allow_redirects=False)
    print "HEAD Request to %s succeedded using system TCP/IP stack.\n" \
        % (proto+domain)
except:
    print "HEAD request to %s failed.\n" % (proto+domain)
    sys.exit(1)

time.sleep(2)

# Send a crafted SYN packet with an arbitrary low TCP TSVal.
# If the server has tcp_tw_recycle enabled, these SYN's should be dropped

# Construct a basic IP packet
ip = IP(src=src_ip, dst=domain)

# Construct a TCP SYN packet
SYN = TCP(sport=src_port, dport=dst_port, flags='S', seq=seq, 
          options=[('Timestamp',(ts_val,0))])

# Send our SYN and store in response in a variable "SYNACK"
print "--[STAGE 2]--"
print "Sending crafted SYN packet with TSVal = %s.\n" % ts_val
SYNACK = sr1((ip/SYN), timeout=3, retry=3, verbose=0)

if SYNACK:
    print "--[RESULT]--"
    print "Got a SYN/ACK response to crafted SYN. TCP_TW_RECYCLE should be OFF.\n"
    # Reset the connection
    RST = TCP(sport=src_port, dport=dst_port, flags="R", seq=seq+1, 
              ack=(SYNACK.seq+1))
    send((ip/RST), verbose=0)
else:
    print "--[RESULT]--"
    print "No response to crafted SYN! TCP_TW_RECYCLE might be ON.\n"
