!/bin/bash
#======================================================================================================================
# Simple rules for basic iptables setup.
#======================================================================================================================

iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

iptables -A INPUT -p ALL -i lo --source 127.0.0.1 --destination 127.0.0.1 -j ACCEPT
iptables -A OUTPUT -p ALL -o lo --source 127.0.0.1 --destination 127.0.0.1 -j ACCEPT

iptables -A INPUT -p tcp -i enp0s9 --dport 22 --source 192.168.192.100 --destination 192.168.92.105 -j ACCEPT
iptables -A OUTPUT -p tcp -o enp0s9 --sport 22 --source 192.168.92.105 --destination 192.168.192.100 -j ACCEPT

iptables -t nat -A POSTROUTING -s 192.168.120.0/24 -d 0/0 -o enp0s9 -j SNAT --to-source 192.168.92.105
iptables -t nat -A POSTROUTING -s 192.168.110.0/24 -d 0/0 -o enp0s9 -j SNAT --to-source 192.168.92.105

iptables -A FORWARD -i enp0s8 -o enp0s9 -s 192.168.120.0/24 -j ACCEPT
iptables -A FORWARD -i enp0s10 -o enp0s9 -s 192.168.110.0/24 -j ACCEPT

iptables -A FORWARD -i enp0s9 -o enp0s8 -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i enp0s9 -o enp0s10 -m state --state ESTABLISHED,RELATED -j ACCEPT

#======================================================================================================================

#======================================================================================================================
echo "Firewall works with simple rules! WARNING: BE CAREFUL!"
#======================================================================================================================

