#!/usr/bin/env python

import nmap
def tcp_connect_scan(target, ports):
    # Create an Nmap PortScanner object
    nm = nmap.PortScanner()

    # Perform a TCP Connect scan on the specified ports
    arguments = f'-p {ports}'
    nm.scan(target, arguments=arguments)

    # Iterate through the scan results and print open ports and their state
    for host in nm.all_hosts():
        print(f"Host: {host}")
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                state = nm[host][proto][port]['state']
                print(f"Port: {port} - State: {state}")


if __name__ == "__main__":
    target = input("Enter the target host or IP address: ")
    ports = input("Enter the ports to scan (e.g., 22,80,443): ")
    tcp_connect_scan(target, ports)
