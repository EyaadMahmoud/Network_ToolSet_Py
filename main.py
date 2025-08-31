import scapy.all as scapy
from scapy.all import ARP,Ether,srp,sniff
from tabulate import tabulate
import ipaddress    
import socket
import tkinter as tk
from tkinter import simpledialog , scrolledtext, messagebox



targetports=[21, 22, 23, 80, 443, 8080] 

#------------Subnet Detection
def find_local_subnet():
    hostname = socket.gethostname() 
    local_ip = socket.gethostbyname(hostname) # get my ip using the hostname 
    network = ipaddress.ip_network(local_ip + '/24', strict=False) #return CIDR notation of IP
    return str(network)
#------------Subnet Detection


#Ethernet frame: Dest MAC , Source MAC , EtherType , Payload


#------------arp scan
def arp_scan(subnet, output_box): #detects MAC add. of active users on network
    print(f"\n Scanning subnet: {subnet}")
    arp_req = scapy.ARP(pdst=str(subnet)) #pdst says which subnet to use , who has this IP
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #create eathernet frame using this dest.MAC 
    arp_req_broadcast = broadcast / arp_req #combine arp req inside broadcast ethernet frame we made
    answered = scapy.srp(arp_req_broadcast, timeout=3, verbose=False)[0] #send/rec our broadcast packet and 0 to return only answered list

    answered_list = []
    for sent,received in answered: #both the sent and received in the answered list
        answered_list.append({"IP": received.psrc, "MAC": received.hwsrc})
        


    if answered_list:
        output_box.insert(tk.END, tabulate(answered_list, headers="keys") + "\n")      
    else:
        output_box.insert(tk.END, "No devices Found" + "\n")
#------------arp scan




#------------TCP scan
def tcp_scan(target_ip , targetports): #FTP(21), SSH(22), Telnet(23), HTTP(80), HTTPS(443), HTTP-alt(8080)
    print(f"\n Scanning ports (TCP) - Target : {target_ip} ")
    Tscan_results=[]
    for port in targetports:
        sock = socket.socket(socket.AF_INET , socket.SOCK_STREAM) #create virtual endpoint using IPV4 and with TCP
        sock.settimeout(1)
        val = sock.connect_ex((target_ip, port)) #grab the IP and the port
        if val == 0: 
            Tscan_results.append((port, "TCP", "OPEN", None, None))
        else:
            Tscan_results.append((port, "TCP", "CLOSED", None, None))
        sock.close()
#append the results of scan wether open or closed
    return Tscan_results
#------------TCP scan


#------------UDP scan
def udp_scan(target_ip , targetports): #FTP(21), SSH(22), Telnet(23), HTTP(80), HTTPS(443), HTTP-alt(8080)
    print("\n Scanning ports (TCP) - Target : {target_ip} ")
    Dscan_results=[]
    for port in targetports:
        sock = socket.socket(socket.AF_INET , socket.SOCK_DGRAM) #create virtual endpoint using IPV4 and with TCP
        sock.settimeout(1)
        
        try:
            sock.sendto(b"" , (target_ip, port)) #send an empty byte string to targetIP

            response = sock.recvfrom(1024)  #wait until 1024 bytes are recieved
            rawbytes = response[0] #raw bytes recieved
            senderaddress = response[1] # IP,PORT of sender

            Dscan_results.append((port, "UDP", "OPEN", rawbytes, senderaddress)) 

        except socket.timeout:
            Dscan_results.append((port, "UDP", "OPEN-Timeout", None,None)) #no rawbytes or senderaddress needed 
        except Exception: #closed port
            Dscan_results.append((port, "UDP", "CLOSED", None,None))

        finally:
            sock.close()
    return Dscan_results
#------------UDP scan

#-----Combine UDP & TCP scan results
def udp_and_tcp(target_ip , targetports):
    return tcp_scan(target_ip, targetports) + udp_scan(target_ip, targetports)






#-------Packet Sniffer
def packet_sniffer(interf, output_box):
    output_box.insert(tk.END, f"Performing Sniffing on {interf}")

    def process_packet(packet): #how to process our packet
        if packet.haslayer(scapy.IP): #make sure packet scapy IP checks out 
            src = packet[scapy.IP].src
            dest = packet[scapy.IP].dest
            output_box.insert(tk.END, f"Source: {src} --- Destination: {dest}\n")
            output_box.after(0, lambda: output_box.insert(tk.END, f"Source: {src} --- Destination: {dest}\n"))
    scapy.sniff(iface=interf , prn=process_packet, store=False)
#-------Packet Sniffer


#-------Converting the functions into user interface GUI
def tk_subnet_auto_scan(output_box):
    subnet = find_local_subnet() 
    output_box.insert(tk.END, f"The Local Detected Subnet is: {subnet} \n")
    arp_scan(subnet, output_box)

def tk_subnet_custom_scan(output_box):    
    customsubentry = simpledialog.askstring("Custom Subnet", "Enter your Subnet Manually:") 
    if customsubentry:
        subnet = ipaddress.ip_network(customsubentry, strict=False)
        arp_scan(subnet, output_box)   

def tk_udp_and_tcp(output_box):
    target_ip = simpledialog.askstring("Port Scan", "Enter Target IP for Port Scan:") 
    if target_ip:
        scan_results = udp_and_tcp(target_ip, targetports)
        output_box.insert(tk.END, "Custom Scan Results: \n")
        output_box.insert(tk.END, tabulate(scan_results, headers=["Port", "Protocol", "Status", "Raw Bytes", "Sender Address"]) + "\n")

import threading

def tk_packet_sniffer(output_box):
    interf = simpledialog.askstring("Packet Sniffer", "Enter interface preferred (e.g., eth0, wlan0):")
    if interf:
        threading.Thread(target=packet_sniffer, args=(interf, output_box), daemon=True).start() #threading to prevent freezing from running on main thread


#-------Converting the functions into user interface GUI



#---------Main GUI
def main_gui():
    root = tk.Tk()
    root.title("Network ToolSet")
    root.geometry("800x600")

    #text area
    output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD , width= 90, height=30)
    output_box.pack(padx=20 , pady=20)

    #buton
    button_frame = tk.Frame(root)
    button_frame.pack(pady=20)   

     # Add buttons (arranged in one row for simplicity)
    btn_auto = tk.Button(button_frame, text="Auto Network Scan",
                         command=lambda: tk_subnet_auto_scan(output_box))
    btn_auto.pack(side=tk.LEFT, padx=5)

    btn_custom = tk.Button(button_frame, text="Custom Network Scan",
                           command=lambda: tk_subnet_custom_scan(output_box))
    btn_custom.pack(side=tk.LEFT, padx=5)

    btn_ports = tk.Button(button_frame, text="TCP + UDP Port Scan",
                          command=lambda: tk_udp_and_tcp(output_box))
    btn_ports.pack(side=tk.LEFT, padx=5)

    btn_sniffer = tk.Button(button_frame, text="Packet Sniffer",
                            command=lambda: tk_packet_sniffer(output_box))
    btn_sniffer.pack(side=tk.LEFT, padx=5)

    btn_exit = tk.Button(button_frame, text="Exit", command=root.quit)
    btn_exit.pack(side=tk.LEFT, padx=5)

    # Start GUI loop
    root.mainloop()



if __name__ == "__main__":
    main_gui()

