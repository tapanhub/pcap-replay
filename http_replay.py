#!/bin/python
import os
import sys, getopt
#sys.path.append('/usr/lib/python2.6/site-packages/')
from scapy.all import *
version="1.0.0"


def get_contentlen(req):
	r=req.split("\r\n")
	for l in r:
		if l.find("Content-Length:") != -1:
			return int(l.split(':')[1])

class pcap_file():
	def __init__(self, *args, **kwargs):
		self.pcapfile=kwargs['inputfile']
		self.serverip=kwargs['serverip']
		self.clientip=kwargs['clientip']
		self.serverport=kwargs['serverport']
		self.outfile=kwargs['outputfile']
		if self.serverport == '':
			self.serverport=80
		self.clientreqs=[]
		if self.outfile == '':
			self.outfile= self.pcapfile + ".sh"
		try:
			self.packets=rdpcap(self.pcapfile)
		except IOError as e:
			print("Unable to open file: %s" % (self.pcapfile))
			print(e)
			sys.exit(-1)
	def find_clientreq(self):
		cr=[p for p in self.packets if IP in p and ( p[IP].src == self.clientip ) and (p[IP].dst == self.serverip ) and TCP in p and p[TCP].dport== self.serverport]
		streams=[p for p in self.packets if IP in p and ( p[IP].src == self.clientip or p[IP].src == self.serverip) and (p[IP].dst == self.serverip or p[IP].dst == self.clientip ) and TCP in p and (p[TCP].dport== self.serverport or p[TCP].sport== self.serverport) ]
		print "packets in the pcapfile=\t%d\nhttp packets between client & server=\t%d\n" % (len(self.packets), len(streams))
		if len(streams) < 3:
			print "please specify correct pcapfile/ip addresses\n"
			sys.exit(1)

		request_details={'load':'', 'time':'', 'setcookie':0}
		server_reply_found=0
		client_req_found=0
		private_port=0
		reassemble=0
		for pkt in streams:
			if ( pkt[IP].src == self.clientip ) and (pkt[IP].dst == self.serverip ) and pkt[TCP].dport== self.serverport:
				if Raw in pkt and pkt.getlayer(Raw).load !=  'NoneType':
					if client_req_found == 1 and reassemble == 0:
						self.clientreqs.append(request_details)
						server_reply_found=0
						client_req_found=0
						private_port=0
						request_details={'load':'', 'time':'', 'setcookie':0}


					if private_port == 0:
						private_port=pkt[TCP].sport
						request_details['time']=pkt.time

					pkt_load=request_details['load']+pkt.getlayer(Raw).load
					if pkt_load[:3] == "GET" or pkt_load[:4]== "POST":
						request_details['load']=pkt_load
						if pkt_load[:3] == "GET":
							if pkt_load.find("\r\n\r\n") == -1:
								client_req_found+=1
								reassemble=1
								continue
							else:
								reassemble=0
							client_req_found+=1
						elif pkt_load[:4] == "POST":
							cl=get_contentlen(pkt_load)	
							pd=pkt_load.split("\r\n\r\n")
							if len(pd) < 2 or len(pd[1]) < cl:
								client_req_found+=1
								reassemble=1
								continue
							else:
								reassemble=0
							client_req_found+=1
					
						
			elif ( pkt[IP].src == self.serverip ) and (pkt[IP].dst == self.clientip ) and pkt[TCP].sport== self.serverport and pkt[TCP].dport == private_port:
				if Raw in pkt and pkt.getlayer(Raw).load !=  'NoneType':
					server_reply_found+=1
					lines=pkt.getlayer(Raw).load.split("\r\n")
					for line in lines:
						if line[:15].find("Set-Cookie: ") != -1:
							request_details['setcookie']=1
							break
			if client_req_found >= 1 and server_reply_found >= 1:
				self.clientreqs.append(request_details)
				server_reply_found=0
				client_req_found=0
				private_port=0
				request_details={'load':'', 'time':'', 'setcookie':0}
		if len(self.clientreqs) == 0:
			print "no http request found\n"
			sys.exit(1)
	def gen_script(self):
		try: 
			of=open(self.outfile, "w") 
                except IOError as e: 
                        print(e) 
                        sys.exit(-1)
		adddelay="""
	et=$(date +%s)
        diff=$((et - st))
        moresleep=$((extra_delay - diff))
	if [ $applydelay == 1 ]; then
        	[ $moresleep -ge 0 2>/dev/null ] && sleep $moresleep
	fi
"""

		startscript="""
#!/bin/bash
applydelay=0
extra_delay=0
delayedget()
{
        st=$(date +%s)
        wget $*
        et=$(date +%s)
        diff=$((et - st))
        moresleep=$((extra_delay - diff))
	if [ $applydelay == 1 ]; then
        	[ $moresleep -ge 0 2>/dev/null ] && sleep $moresleep
	fi
}

start_replay()
{

"""

		
                of.write(startscript)
 
		lasttime=self.clientreqs[0]['time']
		setcookie=0
		cookiefile=".%s_cookie.txt" % (self.outfile)
		setcookiestr=""
		
		for req  in self.clientreqs:
			cmd=''
			getreq=''
			url=''
			found_postdata=0
			postdata=''
			delay=(req['time'] - lasttime)
			lasttime=req['time']
			load=req['load']
			if delay >= 1:
                		of.write("\textra_delay=%d\n\tst=$(date +%%s)\n" % (delay))
			if load[0:6].find("GET ") != -1:
				for line in load.split("\r\n"):
					if line[0:3] == "GET":
						getreq=line.split(" ")[1]
						continue
					if line[0:5] == "Host:":
						url=line.split(" ")[1]
						continue
					elif line == '' or line[:8].find("Cookie:") != -1 :
						continue
					else:
						cmd = "%s\t--header='%s' \\\n" % (cmd, line)
				#print "req['setcookie']=%s and setcookie = %d\n" % (req['setcookie'], setcookie)

				if req['setcookie'] == 1:
					setcookiestr="--keep-session-cookies --save-cookies %s" % (cookiefile)
					setcookie=1
				elif req['setcookie'] != 1 and setcookie==1:
					setcookiestr="--load-cookies %s" % (cookiefile)
				else:
					setcookiestr=""

				cmd = "\twget -O /dev/null %s %s \t\"http://%s%s\"\n" % (setcookiestr, cmd, url, getreq)
                		of.write(cmd)
					
			elif load[0:6].find("POST ") != -1:
				for line in load.split("\r\n")[:-1]:
					if line[0:4] == "POST":
						postreq=line.split(" ")[1]
						continue
					if line[0:5] == "Host:":
						url=line.split(" ")[1]
						continue
					elif line == '' or line[:8].find("Cookie:") != -1 :
						continue
					elif line.find('Content-Length:') != -1:
						postdata=load.split("\r\n")[-1]
					else:
						cmd = "%s\t--header='%s' \\\n" % (cmd, line)
				if req['setcookie'] == 1:
					setcookiestr="--keep-session-cookies --save-cookies %s" % (cookiefile)
					setcookie=1
				elif req['setcookie'] != 1 and setcookie==1:
					setcookiestr="--load-cookies %s" % (cookiefile)
				else:
					setcookiestr=""

				cmd = "\twget -O /dev/null %s --post-data='%s' %s \t\"http://%s%s\"\n" % (setcookiestr, postdata, cmd, url, postreq)
                		of.write(cmd)
			if delay >= 1:
                		of.write(adddelay)
		endscript="""
}

case $1 in
-h)
	echo $0 1 # to enable replay delay as it is in the pcap file
	exit 1
	;;
1)
	applydelay=1
	;;
*)
	;;
esac
start_replay
"""
                of.write(endscript)
               	of.close()
def main(argv):
	inputopts={'inputfile':'', 'outputfile':'', 'serverip':'', 'clientip':'', 'serverport':''}
	try:
		opts, args = getopt.getopt(argv[1:], "vhi:o:s:c:p:", ["version", "ifile=","ofile=","cip=", "sip=", "port="])
	except getopt.GetoptError:
		print '%s  -i <input pcap file> -s <serverip> -c <clientip> [-o <output script name>] [-p <server port>]' % (argv[0])
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print '%s  -i <input pcap file> -s <serverip> -c <clientip> [-o <output script name>] [-p <server port>]' % (argv[0])
			sys.exit(2)
		elif opt in ("-i", "--ifile"):
			inputopts['inputfile'] = arg
		elif opt in ("-o", "--ofile"):
			inputopts['outputfile'] = arg
		elif opt in ("-c", "--cip"):
			inputopts['clientip'] = arg
		elif opt in ("-s", "--sip"):
			inputopts['serverip'] = arg
		elif opt in ("-v", "--version"):
			print "%s %s" % (argv[0], version)
			sys.exit(0)
	if inputopts['inputfile'] == '' or inputopts['clientip'] == '' or inputopts['serverip']== '':
		print '%s  -i <input pcap file> -s <serverip> -c <clientip> [-o <output script name>] [-p <server port>]' % (argv[0])
		sys.exit(2)

	pcap=pcap_file(**inputopts)
	pcap.find_clientreq()
	pcap.gen_script()

if __name__ == '__main__':
	try:
		main(sys.argv)
	except KeyboardInterrupt:
		print 'Interrupted'
	try:
		sys.exit(0)
	except SystemExit:
		os._exit(0)
