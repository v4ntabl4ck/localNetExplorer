# LocalNet Explorer
LocalNet Explorer is a Python tool for network scanning, supporting ARP and ICMP protocols.
It's designed to identify devices on a LAN efficiently and ethically.
With capabilities for CIDR-based target specification and randomized request timing, it's a versatile tool for network analysis and diagnostics.

Note: Use responsibly on networks you have permission to scan.

To scan your network using LocalNet Explorer, run the script with sudo (required for network scanning permissions), 
followed by the target IP range in CIDR notation, and specify the scan type (-a for ARP scan or -i for ICMP scan).
```bash
sudo python localnet_explorer.py 10.0.0.0/24 -a