
import scapy.all as scapy
from scapy_http import http


def sniff_network(interface):  
    scapy.sniff(iface=interface,store=False,prn=analyze_packets)    
         
         
def analyze_packets(packet):     
    packet.show()
    
    
sniff_network("eth0")     

