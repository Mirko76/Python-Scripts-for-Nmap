#!/usr/bin/env python

import subprocess

target = '127.0.0.1'
# Scan a specific UDP port (e.g., port 53)
# command = f'sudo nmap -sU -p 53 {target}'
# Scan a range of UDP ports (e.g., ports 53 to 80)

command = f'sudo nmap -sU -p 67-69 {target}'

try:
    output = subprocess.check_output(command, shell=True)
    print(output.decode())
except subprocess.CalledProcessError as e:
    print(f"Error: {e}")
