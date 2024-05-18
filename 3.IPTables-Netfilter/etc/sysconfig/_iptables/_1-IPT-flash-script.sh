!/bin/bash
#======================================================================================================================
# Flash all chains and rules and setup ACCEPT ALL policies
#======================================================================================================================
#
# Reset All Rules
#
iptables -F
iptables -X
iptables -Z
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t raw -F
iptables -t raw -X
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
#
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
#======================================================================================================================
echo "Firewall completely stopped! WARNING: THIS HOST HAS NO FIREWALL RUNNING!"
#======================================================================================================================

