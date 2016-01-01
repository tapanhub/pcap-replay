# pcap-replay
 converts captured pcap file to script to replay/automate different protocols

http_replay.py: converts captured pcap file to bash script to replay http

http_replay.py is a python script. It uses scapy to read pcap file and extracts http requests.
Then  it generates portable bash script containing  wget commands to replay the http client request in exact manner.
The bash script can be used to automate repetative tasks such as configuring router, modem etc..

Current version (1.0.0) supports following features
1. Converts http requests from pcap file to bash script
2. captures the required delay in bash script, so that it will avoid any timing requirement between requests
3. Automatically takes care of login session cookies
4. Handles if http requests spawn across multiple packets

Usage:
./http_replay.py  -i <input pcap file> -s <serverip> -c <clientip> [-o <output script name>] [-p <server port>]
e.g.
./http_replay.py  -i netgear_configurewan.pcap -c 192.168.1.6 -s 192.168.1.1 -o netgear_configurewan.sh


please visit http://www.secdev.org/ for scapy license
For any query please contact me at tapanigit@gmail.com 
