#!/usr/bin/python

import os;
import sys;
import threading;

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

ip_list = [];
output_folder = "";


if not len(sys.argv) > 2:
	sys.exit("This programs needs 2 arguments: 1: IP list seperated by commas, 2: Output folder (absolute path)")

ip_list = sys.argv[1].split(",");
output_folder = sys.argv[2];

global ip_count;
ip_count = len(ip_list) - 1;
ip_count = 0;

# Creating main folder
os.makedirs(output_folder);
# Creating folders inside:
for ip in ip_list:
	os.makedirs(output_folder+ip.strip('\n'))
	os.makedirs(output_folder+ip.strip('\n')+ "/nmap_top_100")
        os.makedirs(output_folder+ip.strip('\n')+ "/nmap_version_vuln")
        os.makedirs(output_folder+ip.strip('\n')+ "/nmap_full_syn")
        os.makedirs(output_folder+ip.strip('\n')+ "/nmap_udp")
        os.makedirs(output_folder+ip.strip('\n')+ "/scans")
	os.makedirs(output_folder+ip.strip('\n')+ "/exploits")





# IP count functions
def getipcount():
	return str(ip_count);
def upipcount():
	global ip_count;
	ip_count = ip_count+1;

#sys.exit(getipcount());


def exe(command):
	return os.popen(command).read()

# Print out message on screen per IP as to what has completed.
def output(message, code): #starting exec, result exec
	if code == 1: # new action
		print bcolors.BOLD + bcolors.OKBLUE + message + bcolors.ENDC
	elif (code == 2):
                print bcolors.BOLD + bcolors.OKGREEN + message + bcolors.ENDC

def nmap_worker():
	ipcount = getipcount();
	upipcount();
	ip = ip_list[int(ipcount)];

	# top 100 SYN scan 
	output("[*] Starting top 100 scan on IP: "+ip, 1)
	scan_1_results = exe("nmap --top-ports=1000 -sS "+ip+" -oA "+output_folder+ip+"/nmap_top_100/nmap_top_100");
	output("[*] Top 100 scan has finished for IP: "+ip, 2)

	# Cherrymap results:
        output("[*] Creating cherrymap file for IP: "+ip, 1)
	exe("cherrymap "+output_folder+ip+"/nmap_top_100/. -o "+output_folder+"/"+ip+"/")
	output("[*] Cherrymap file created for IP: "+ip, 2)

	# Nmap Vuln/Version scan on ports, NOT filtered only, but OPEN OR FILTERED only
        output("[*] Starting Vuln/version scan on IP: "+ip, 1)

	ports = exe("cat "+output_folder+ip+"/nmap_top_100/nmap_top_100.nmap | grep open | cut -d '/' -f 1")

	ports_to_scan = ports.split("\n");	
	ports_to_scan = filter(None, ports_to_scan) # fastest
	port_string = "";

	for port in ports_to_scan:
		port_string += port + ","
	port_string = port_string[:-1];	

	exe("nmap -sV -p"+port_string+" -sS "+ip+" -oA "+output_folder+ip+"/nmap_version_vuln/nmap_vuln_version "+"--script vuln")
        output("[*] Vuln/version scan has finished for IP: "+ip, 2)

	# FULL SYN scan, compare ports to do a version/vuln scan on these ports?
        output("[*] Starting full SYN scan on IP: "+ip, 1)
	exe("nmap -sS -p- "+ip+" -oA "+output_folder+ip+"/nmap_full_syn/nmap_full_syn")
        output("[*] full SYN scan has finished for IP: "+ip, 2)

	# UDP scan
	output("[*] Starting UDP scan on IP: "+ip, 1)
        exe("nmap -sU "+ip+" -oA "+output_folder+ip+"/nmap_udp/nmap_udp")
        output("[*] UDP scan has finished for IP: "+ip, 2)
        output("[*] ALL scans have finished for IP: "+ip, 2)

threads = []
for ip in ip_list:
    t = threading.Thread(target=nmap_worker)
    threads.append(t)
    t.start()
