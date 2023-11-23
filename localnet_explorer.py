import random
import sys
import argparse
import ipaddress
import logging
from scapy.all import srp, sr1
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP

# configure logging
logging.getLogger("scapy").setLevel(logging.CRITICAL)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_ip_range(cidr_notation):
    try:
        network = ipaddress.ip_network(cidr_notation, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        logging.error(f"Error: {e}")
        return []


def scan_arp(ip_list):
    # Function to perform an ARP scan
    logging.info("Starting ARP scan...")
    for ip in ip_list:
        try:
            # random delay so scan is not so easy predictable
            req_time = random.uniform(0.1, 0.5)

            # send ARP request with broadcast MAC and target IP
            ans, unans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                timeout=2,
                verbose=False,
                inter=req_time,
            )
            responded = False
            for sent, received in ans:
                # check if 'received' packet has ARP layer and is an ARP replay
                if (
                    received.haslayer(ARP) and received[ARP].op == 2
                ):  # ARP reply is op code 2
                    logging.info(f"IP: {received.psrc}, MAC: {received.hwsrc}")
                    responded = True
            if not responded:
                logging.info(f"No valid ARP response received from IP: {ip}")
        except Exception as e:
            logging.error(f"Error scanning {ip}: {e}")


def scan_icmp(ip_list):
    # Function to perform an ICMP scan
    logging.info("Starting ICMP scan...")
    for ip in ip_list:
        try:
            # send ICMP request with broadcast MAC and target IP
            ans = sr1(IP(dst=ip) / ICMP(), timeout=2, verbose=False)
            if ans:
                logging.info(f"IP: {ans[IP].src} responded to ICMP")
            else:
                logging.info(f"No response from IP: {ip}")
        except Exception as e:
            logging.error(f"Error scanning {ip}: {e}")


def main():
    parser = argparse.ArgumentParser(description="LocalNet Scanner")
    parser.add_argument(
        "ip_range", type=str, help="IP range to scan, e.g., 192.168.0.1/24"
    )
    parser.add_argument("-a", "--arp", action="store_true", help="Perform an ARP scan")
    parser.add_argument(
        "-i", "--icmp", action="store_true", help="Perform an ICMP scan"
    )

    args = parser.parse_args()

    try:
        ip_list = get_ip_range(args.ip_range)
    except ValueError as e:
        logging.error(e)
        sys.exit(1)

    if args.arp:
        scan_arp(ip_list)
    elif args.icmp:
        scan_icmp(ip_list)
    else:
        logging.error("No scan type specified. Use -a for ARP scan or -i for ICMP scan.")
        sys.exit(1)


if __name__ == "__main__":
    main()
