import scapy.all as scapy
import optparse

try:
    def get_user_input():
        parse_object = optparse.OptionParser()
        parse_object.add_option("-i","--ipaddress",default="192.168.1.0/24",dest="ip_address",help="Enter IP Address")

        (input,arguments) = parse_object.parse_args()
        if not input.ip_address :
            print("Please enter ip address!")
        return  input

    def scan_network(ip):
        arp_req_packet = scapy.ARP(pdst=ip)
        broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        combined_packet = broadcast_packet/arp_req_packet
        (answered_list,unanswered_list) = scapy.srp(combined_packet,timeout=1)
        answered_list.summary()

    user_ip_address = get_user_input()
    scan_network(user_ip_address.ip_address)

except PermissionError:
    print("\nYou must be root!")
