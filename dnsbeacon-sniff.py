''' 	DNS Beacon Detector 
	Written by slacker007 of CyberSyndicates.com & the OFFtoolKit
	http://www.cybertsyndicates.com 
'''
import pprint
import subprocess as sp
import socket
from struct import *
import datetime
import sys
import impacket
from impacket import ImpactDecoder
import copy
import socket
import hashlib

try: 
	import pcapy
except: 
	print "\npcapy module is not installed on your system"
	print "please run: sudo apt-get update; apt-get upgrade; apt-get install python-pcapy"

def main(argv):
	#list all net interfaces 
	net_devices = pcapy.findalldevs()
	print net_devices

	#choose net_device
	print "Available Network Interface: "
	for x in net_devices : 
		print x

	dev_choice = raw_input("Please choose interface to sniff " )
	print "Sniffing Device: " + dev_choice

	capture = pcapy.open_live(dev_choice, 65536, 1, 0)
	# capture == the live instance


	# comment the line below to capture ALL traffic or edit to set BPF filter for wanted traffic
	packet_reader=capture.setfilter('((udp) && (dst port 53) && (ip[41] = 0x61) && (ip[42] = 0x70) && (ip[43] = 0x69))') 
	print "Listening on %s: NET: %s, MASK: %s, LINKTYPE: %d" % (dev_choice, capture.getnet(), capture.getmask(), capture.datalink())
	
	ascii_list = []
	domain_list = []
	hash_list = []

	#start packet capture
	while(1): 
		(header, packet) = capture.next()
		# Uncomment the line below to display header information for each packet
#		print('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
		packet_parser(packet)
		dec_list, sub_domain, root_domain = decoder(header, packet)
		dec2ascii(sub_domain, hash_list, domain_list)

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a):
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
	return b


#Use impactDecder to decode packets
def decoder (packet_header, packet):
	
	dec = impacket.ImpactDecoder.EthDecoder()
	ether=dec.decode(packet)
	ipHeader=ether.child()
#	List of decimal to ascii conversion of top-level domains | could be used to add future functionality
#	domain_conv = [('99111109','com'),('677977','COM'),('101100117','edu'),('696885','EDU'),('103111118','gov'),('717986','GOV'),('110101116','net'),('786984','NET'),('109105108','mil'),('777376','MIL'),('111114103','org'),('798271','ORG')]
	dec_list = []
	packetType=ipHeader.child().protocol
	
	if packetType == 17:
		udpHeader=ipHeader.child()

	payload2decimal = udpHeader.child().get_bytes().tolist()
	total_len = len(payload2decimal) - 1
	root_domain = []
	sub_domain = []
	x = 0
	temp = 0
	temp2 = True
	temp3 = True
#	Converts Payload to Decimal and carves out top-level domain and subdomain
	for i in payload2decimal:
		temp = payload2decimal[total_len] 
		if str(payload2decimal[total_len]) in ('3','9', '7', '5','12'):
			dec_list.append(46)
			total_len = total_len - 1
			if temp == 3 and temp2 == True: 
				root_domain = copy.deepcopy(dec_list)
				temp2 = False
			elif x == 1 and temp3 == True: 
				sub_domain = copy.deepcopy(dec_list)
				temp3 = False
				return dec_list, sub_domain, root_domain
			x = x + 1
		elif (total_len > 0):
			if (temp > 32):
				dec_list.append(payload2decimal[total_len])				
			total_len = total_len - 1

	return dec_list, sub_domain, root_domain
# Resolves string passed in as variable 'domain' and appends it to running list of domains 'domain_list'
def resolver(domain, domain_list):
	blank = sp.call('clear', shell=True)
	try:
		domain_info = socket.gethostbyname(domain)
		domain_list.append((domain, domain_info))
		blank
		pprint.pprint(domain_list)
		return
	except:
		domain_list.append((domain, 'UNABLE TO RESOLVE URL TO IP'))
		blank
		pprint.pprint(domain_list)
		return

# Converts from decimal to ascii, pads where necessary, hashes results and compares against list of hashes to prevent duplicate resolves
def dec2ascii (dec_list, hash_list, domain_list):
	m = hashlib.md5()
	ascii_list = []
	ascii_url = ''
	i = 1
	ii = 1
	last = len(ascii_list) - 1
	for decBytes in dec_list:
		if decBytes in range(32,127): #Look for decimal ranges 32-126 to convert from decimal to hex
			hexByte = str(hex(decBytes)).lstrip("0x")
			if len(hexByte) == 1:  #Pad hex value w/ 0 if not already a 2 digit number
				hexByte = "0" + hexByte
			asciiByte = hexByte.decode('hex') # conver hex value to ascii and append to ascii list
			ascii_list.append(asciiByte)
	ascii_list = copy.deepcopy(ascii_list[::-1])
	WWW = ['W','W','W']
	www = ['w','w','w']
        if ascii_list[1:4:1] == www or (str((ascii_list[1:4:1])) == WWW):
		if ((ascii_list[4]) == '.'):
        	        pass
                else:
                        ascii_list.insert(4,'.')

	for i in ascii_list[1:]:
		ascii_url = ascii_url + str(i)

	if ascii_url == '':
		return 

	m.update(ascii_url)
	hash =  m.hexdigest() 

	if len(hash_list) == 0:
		hash_list.append(hash)
		return resolver(ascii_url, domain_list)
	else:
		for x in hash_list:
			if x == hash:
				return 
		hash_list.append(hash)
		return resolver(ascii_url, domain_list)

#Packet Parser
def packet_parser(packet):
#	parse eth header
	eth_length = 14
	eth_header = packet[:eth_length]
	eth = unpack('!6s6sH', eth_header)
	eth_protocol = socket.ntohs(eth[2])
#	Uncomment line below to print eth header information	
	#print 'Destination MAC: ' + eth_addr(packet[0:6]) + ' Source MAC: ' + eth_addr(packet[6:12]) + ' Protocol: ' + str(eth_protocol)

	#parse IP packtes, IP Proto number = 8
	if eth_protocol == 8 : 

		#Parse IP Header
		#Take first 20 Characters for the IP header
		ip_header = packet[eth_length:20+eth_length]

		#now unpack 
		iph = unpack('!BBHHHBBH4s4s' , ip_header)
		version_ihl = iph[0]
		version = version_ihl >> 4
		ihl = version_ihl & 0xF
		iph_length = ihl * 4
		ttl = iph[5]
		protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8]);
		d_addr = socket.inet_ntoa(iph[9]);
#		Uncomment line below to print IP header information
		#print 'Version: ' + str(version) + ' IP Header Length: ' + str(ihl) + ' TTL: ' + str(ttl) + ' Protocol: ' + str(protocol) + ' Source Address: ' + str(s_addr) + ' Destination Address: ' + str(d_addr)


		#UDP packets
	if protocol == 17 :
		u = iph_length + eth_length
		udph_length = 8
		udp_header = packet[u:u+8]

		#now unpack them :)
		udph = unpack('!HHHH' , udp_header)
		source_port = udph[0]
		dest_port = udph[1]
		length = udph[2]
		checksum = udph[3]
		
#		print 'Source Port: ' + str(source_port) + ' Dest Port: ' + str(dest_port) + ' Length: ' + str(length) + ' Checksum: ' + str(checksum)
			
		h_size = eth_length + iph_length + udph_length
		data_size = len(packet) - h_size
		
		#get data from the packet
		data = packet[h_size:]
#		Uncomment the line below to print data from UDP packet			
		#print 'Data : ' + data

#		some other IP packet like IGMP
	else :
		print ' Protocol other than UDP '

if __name__ == "__main__":
  main(sys.argv)
