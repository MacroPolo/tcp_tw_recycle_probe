# Overview
Script to test whether a target webserver has the `tcp_tw_recycle`
option enabled.

Python requests is first used to make a HEAD request to the target webserver.
The "Connection: Close" header is set to ensure that the server ends up
in the TIME-WAIT state. 

If the HEAD request completes, Scapy is used to send a crafted SYN packet to the
same destination IP/port with a  user defined Timestamp value (100 by default).
Lack of SYN/ACK response would indicate that the server has dropped the second
connection attempt and may have tcp_tw_recycle enabled.

# Prerequisites

1. The Python Requests module needs to be [installed](http://docs.python-requests.org/en/master/user/install/). Typically:
```
pip install requests
```
2. Scapy will also need to be installed in order to send handcrafted TCP packets. Installation instructions [here](http://www.secdev.org/projects/scapy/doc/installation.html).

# Usage

```
usage: main.py [-h] -d DOMAIN -s SOURCE_IP [-p DST_PORT] [-t TSVAL]

Detect linux servers with tcp_tw_recycle enabled

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target domain
  -s SOURCE_IP, --source-ip SOURCE_IP
                        Source IP address
  -p DST_PORT, --dst-port DST_PORT
                        Destination port
  -t TSVAL, --tsval TSVAL
                        Crafted timestamp value
```

# Examples

Probing a server which has `tcp_tw_recycle` enabled:

```
root@ubuntu:/tmp# python main.py -d www.elegantthemes.com -s 192.168.0.56 -t 50
---------------------------------------------
Testing: http://www.elegantthemes.com
---------------------------------------------
--[STAGE 1]--
Sending HEAD request to server through OS TCP/IP Stack
HEAD Request to http://www.elegantthemes.com succeedded using system TCP/IP stack.

--[STAGE 2]--
Sending crafted SYN packet with TSVal = 50.

--[RESULT]--
No response to crafted SYN! TCP_TW_RECYCLE might be ON.

```


