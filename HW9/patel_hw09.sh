#!/bin/bash

# Parth Patel
# patel344
# Homework 9
# March 28, 2017


# Flush out previous rules
sudo iptables -F
sudo iptables -t nat -F

# Place no restrictions on outbound packets
sudo iptables -I OUTPUT 1 -j ACCEPT

# Block a list of specific IP Addresses for all Incoming Connections
declare -a IPS=("192.168.6.100" "192.168.6.1" "192.168.6.29");
for x in ${IPS[@]}
do
	sudo iptables -A INPUT -s $x -j DROP
done

# Block your computer from being pinged by all other hosts
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Set up port forwarding from unused port 422 to port 22

# First allow incoming connections on port 422
sudo iptables -A INPUT -p tcp --dport 422 -j ACCEPT

# Accept port forwarding to ssh port 22
sudo iptables -A FORWARD -p tcp --dport 22 -j ACCEPT

# Allow for SSH access to this machine only from ecn.purdue.edu domain
sudo iptables -A INPUT ! -s ecn.purdue.edu -p tcp --dport 22 -j REJECT

# Unsure if this line is redundant or necessary
sudo iptables -A INPUT -p tcp -s ecn.purdue.edu --dport 22 -j ACCEPT

# Route traffic that comes from prot 422 to port 22
sudo iptables -t nat -A PREROUTING -p tcp -d 10.0.2.15 --dport 422 -j DNAT --to-destination 10.0.2.15:22

# Allows only a single IP address in the internet to acces my machine for HTTP
sudo iptables -A INPUT -p tcp ! -s 128.168.135.197 --dport 80 -j REJECT

# Again, this may be unecessary
sudo iptables -A INPUT -p tcp -s 128.168.135.197 --dport 80 -j ACCEPT

# Permit Auth/Ident port 113 that is used by somer services like smtp and irc
sudo iptables -A INPUT -p tcp --dport 113 -j ACCEPT
