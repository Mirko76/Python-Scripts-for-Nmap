#!/usr/bin/env python

import nmap

# -Pn: Treat all hosts as online -- skip host discovery
# "Don't Ping" scan on the specified target without specifying the ports to scan, effectively scanning all 65,535 possible TCP ports
# How to use
# $ nmap -Pn 192.168.199.1

def dont_ping_scan(target):
    # Create an Nmap PortScanner object
    nm = nmap.PortScanner()

    # Perform a scan without host discovery (don't ping) and scan all ports
    arguments = '--host-timeout 10m'
    nm.scan(target, arguments=arguments)

    # Iterate through the scan results and print open ports and their state
    for host in nm.all_hosts():
        print(f"Host: {host}")
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                state = nm[host][proto][port]['state']
                print(f"Port: {port} - State: {state}")

if __name__ == "__main__":
    target = input("Enter the target host or IP address: ")
    dont_ping_scan(target)

