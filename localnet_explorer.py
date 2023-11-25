import argparse
import ipaddress
import logging
import random
import sys
from scapy.all import srp
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sr

# configure logging
logging.getLogger("scapy").setLevel(logging.CRITICAL)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def is_valid_cidr(cidr_notation):
    try:
        # ValueError if the CIDR notation is incorrect
        ipaddress.ip_network(cidr_notation, strict=False)
        return True
    except ValueError as e:
        logging.error(f"Invalid CIDR notation: {cidr_notation}. Error: {e}")


def get_ip_range(cidr_notation):
    try:
        network = ipaddress.ip_network(cidr_notation, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        logging.error(f"Error: {e}")
        return []


def scan_arp(ip_list, random_delay=False):
    # Function to perform an ARP scan
    logging.info("Starting ARP scan...")

    # create ARP request for all IPs in the List
    arp_request = [Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip) for ip in ip_list]

    # set delay between request if random_delay is True
    delay = random.uniform(0.1, 0.5) if random_delay else 0

    # Send ARP request and receive responses
    ans, unans = srp(arp_request, timeout=2, verbose=False, inter=delay)

    # Process received responses
    for sent, received in ans:
        # Check if the received packet is an ARP reply
        if received.haslayer(ARP) and received[ARP].op == 2:
            logging.info(f"IP: {received.psrc}, MAC: {received.hwsrc}")
    # Display scan summary
    display_summary("ARP", ip_list, ans, unans)

def scan_icmp(ip_list, random_delay=False):
    # Function to perform an ICMP scan
    logging.info("Starting ICMP scan...")

    # create list of packages to send
    icmp_requests = [IP(dst=ip) / ICMP() for ip in ip_list]

    # set delay between requests if random_delay is True
    delay = random.uniform(0.1, 0.5) if random_delay else 0

    # send ICPM requests and receive response
    ans, unans = sr(icmp_requests, timeout=2, verbose=False, inter=delay)

    # calc total round-trip time (RTT) for all responses
    total_rtt = sum(received.time - sent.sent_time for sent, received in ans)

    # Process received responses
    for sent, received in ans:
        logging.info(f"IP: {received[IP].src} responded in {received.time - sent.sent_time:.6f}  seconds")

    # display scan summary
    display_summary("ICPM", ip_list, ans, unans, total_rtt)


def display_summary(scan_type, ip_list, ans, unans, total_rtt=None):
    total_hosts = len(ip_list)
    responsive_hosts = len(ans)
    unresponsive_hosts = len(unans)
    average_rtt = (total_rtt / responsive_hosts) if total_rtt else None

    logging.info(f"Scan Type: {scan_type}")
    logging.info(f"Total Hosts Scanned: {total_hosts}")
    logging.info(f"Responsive Hosts: {responsive_hosts}")
    logging.info(f"Unresponsive Hosts: {unresponsive_hosts}")
    if average_rtt is not None:
        logging.info(f"Average Response Time: {average_rtt:.6f} seconds")


def main():
    parser = argparse.ArgumentParser(description="LocalNet Scanner")
    parser.add_argument(
        "ip_range", type=str, help="IP range to scan, e.g., 192.168.0.1/24"
    )
    parser.add_argument("-a", "--arp", action="store_true", help="Perform an ARP scan")
    parser.add_argument(
        "-i", "--icmp", action="store_true", help="Perform an ICMP scan"
    )
    parser.add_argument("-d", "--delay", action="store_true", help="Add random delay")

    args = parser.parse_args()

    # validate the IP range
    if not is_valid_cidr(args.ip_range):
        sys.exit(1)

    try:
        ip_list = get_ip_range(args.ip_range)
    except ValueError as e:
        logging.error(e)
        sys.exit(1)

    if args.arp:
        scan_arp(ip_list, args.delay)
    elif args.icmp:
        scan_icmp(ip_list, args.delay)
    else:
        logging.error(
            "No scan type specified. Use -a for ARP scan or -i for ICMP scan."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
