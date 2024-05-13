#!/bin/bash
########################################################################
# BORDER BASTION_HOST FIREWALL TEMPLATE
# Additional tuning and evolution I'll publish in this repo
# git@github.com:it-engineer-pro/FireWalling.git
########################################################################
# PROTECTED SUBNETWORKS PLANE:
# IDSSVS_LAN:192.168.100.0/24
#
# DMZSRV_LAN:192.168.30.0/24
#
# EXTSRV_LAN:192.168.20.0/24
#
# INTSRV_LAN:192.168.10.0/24
#
# OFFICE_LAN:192.168.1.0/24
#
# ISPNET_WAN:10.10.10.0/24
########################################################################

########################################################################
# Setup Base Network Parameters.
# Enable IP forwarding1.
echo 1 > /proc/sys/net/ipv4/ip_forward
#
# Enable TCP SYN Cookie Protection.
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
#
# Enable broadcast echo Protection.
echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
#
# Enable broadcast echo Protection.
echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
#
# Disable Source Routed Packets.
echo "0" > /proc/sys/net/ipv4/conf/all/accept_source_route
#
# Disable ICMP Redirect Acceptance.
echo "0" > /proc/sys/net/ipv4/conf/all/accept_redirects
#
# Don't send Redirect Messages.
echo "0" > /proc/sys/net/ipv4/conf/all/send_redirects
#
# Log packets with impossible addresses.
echo "1" > /proc/sys/net/ipv4/conf/all/log_martians
#

#
# Drop Spoofed Packets coming in on an interface, which, if replied to,
# would result in the reply going out a different interface.
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
    echo "1" > $f
done
#
#
# /sbin/modprobe ip_conntrack_ftp
#
#
########################################################################
#
# Aliaces and shortcuts
#
CON_TRAC="1"                             # Not used.
ACC_AUTH="0"                             # Not used.
SSH_SERVER="0"                           # Not used.
FTP_SERVER="0"                           # Not used.
WEB_SERVER="0"                           # Not used.
SSL_SERVER="0"                           # Not used.
DHCP_CLIENT="0"                          # Not used.
IPT="/sbin/iptables"                     # Location of iptables on your system.
LPB_IF="lo"                              # Local Network Interface.
LPB_SN="127.0.0.0/8"                     # Reserved loopback address range.
CLS_A="10.0.0.0/8"                       # Class A private networks.
CLS_B="172.16.0.0/12"                    # Class B private networks.
CLS_C="192.168.0.0/16"                   # Class C private networks.
CLS_D_MLTCST="224.0.0.0/4"               # Class D multicast addresses.
CLS_E_RESNET="240.0.0.0/5"               # Class E reserved addresses.
BCST_SRC_NET="0.0.0.0/8"                 # Can't be blocked unilaterally with DHCP.
LINK_LCL="169.254.0.0/16"                # Link Local Network.
TEST_NET="192.0.2.0/24"                  # TEST-NET.
BCST_SRC="0.0.0.0"                       # Broadcast source address.
BCST_DEST="255.255.255.255"              # Broadcast destination address.
WTCP_PRTS="1:1023"                       # Well-known, privileged port range. TCP.
WUDP_PRTS="0:1023"                       # Well-known, privileged port range. UDP.
RGST_PRTS="1023:49151"                   # Registered, privileged port range.
DYNC_PRTS="49152:65535"                  # Dynamic, unprivileged port range.
UNPR_PRTS="1024:65535"                   # Unprivileged port range.
#
WAN_IF="enp0s3"                          # External interface.
WAN_IP="10.10.10.10/24"                  # External IP address.
WAN_SN="10.10.10.0/24"                   # External Subnet.
WAN_BR="10.10.10.255/24"                 # External Subnet Broadcast.
#
DMZ_IF="enp0s8"                          # DMZ interface.
DMZ_IP="192.168.30.1/24"                 # DMZ Interface IP address.
DMZ_SN="192.168.30.0/24"                 # DMZ Subnet.
DMZ_BR="192.168.30.255/24"               # DMZ Subnet Broadcast.
#
INT_IF="enp0s9"                          # Internal interface.
INT_IP="192.168.100.1/24"                # Internal Interface IP address.
INT_SN="192.168.100.0/24"                # Internal Subnet.
INT_BR="192.168.100.255/24"              # Internal Subnet Broadcast.
#
# traceroute usually uses -S 32769:65535 -D 33434:33523
TRCRT_SRC_PORTS="32769:65535"            # Traceroute source ports.
TRCRT_DST_PORTS="33434:33523"            # Traceroute destination ports.
NFS_PORT="2049"                          #
LOCKD_PORT="4045"                        #
SOCKS_PORT="1080"                        #
OPENWINDOWS_PORT="2000"                  #
XWINDOW_PORTS="6000:6063"                #
SQUID_PORT="3128"                        #
#
MY_ISP="my.isp.address.range"            # ISP server & NOC address range.
NS1="192.168.30.15"                      # Address of a local name server.
NS2="isp.name.server.2"                  # Address of a remote name server.
POP_SRV="192.168.30.11"                  # Address of a remote pop server.
MAIL_SRV="192.168.30.11"                 # Address of a remote mail gateway.
TIME_SRV="192.168.30.15"                 # Address of a remote time server.
DHCP_SRV="isp.dhcp.server"               # Address of your ISP dhcp server.
SSH_CLIENT="some.ssh.client"             # Remote Support IP address.

########################################################################

########################################################################
# Reset All Rules.
#
$IPT -F
$IPT -X
$IPT -Z
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X
$IPT -t raw -F
$IPT -t raw -X
$IPT --flush
$IPT --table nat --flush
$IPT --delete-chain
$IPT --table nat --delete-chain
#
########################################################################
# Setup default policies.
#
$IPT -P INPUT   DROP
$IPT -P OUTPUT  DROP
$IPT -P FORWARD DROP
#

########################################################################
# Describe User Defined Chains.
#
USER_CHAINS="EXT-input EXT-output EXT-icmp-in EXT-icmp-out EXT-log-in EXT-log-out \
             tcp-state-flags source-address-check
             local-dns-server-query local-tcp-client-request \
             remote-tcp-client-request local-udp-client-request \
             local-dhcp-client-query \
             log-tcp-state connection-tracking
             destination-address-check remote-dns-server-response \
             remote-tcp-server-response local-tcp-server-response \
             remote-udp-server-response remote-dhcp-server-response "
#
########################################################################
# Create the user-defined chains.
#
for i in $USER_CHAINS; do
    $IPT -N $i
done
#

########################################################################
# Define custom chain LOG_DROP for log dropped packets.
#
$IPT -N LOG_DROP
$IPT -A LOG_DROP -m limit --limit 10/min -j LOG --log-prefix "IPT-LogDrop: " --log-level 7
$IPT -A LOG_DROP -j DROP

########################################################################
# Define custom chain LOGGING for diagnostic and control.
# Packets will be rejected when not redirected to other chains.
#
$IPT -N LOGGING
$IPT -A INPUT   -j LOGGING
$IPT -A OUTPUT  -j LOGGING
$IPT -A FORWARD -j LOGGING
$IPT -A LOGGING -m limit --limit 60/min -j LOG --log-prefix "IPT-LogPass: " --log-level 4
$IPT -A LOGGING -j REJECT
#

########################################################################
# Rules for cleaning traffic.
#
$IPT -A INPUT  -m state --state INVALID -j LOG --log-prefix "IPT-LogINVALID-input: "
$IPT -A INPUT  -m state --state INVALID -j DROP
$IPT -A OUTPUT -m state --state INVALID -j LOG --log-prefix "IPT-LogINVALID-output: "
$IPT -A OUTPUT -m state --state INVALID -j DROP

#
# Drop bad packets in INPUT chain. Stealth Scans and TCP State Flags.
# Christmas tree packets
$IPT -A INPUT -p tcp -m tcp --tcp-flags ALL FIN,PSH,URG -j LOG_DROP
#
# Invalid TCP packets
# New incoming TCP connection packets without SYN flag set
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j LOG_DROP
#
# New state packet with SYN,ACK set
$IPT -A INPUT -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j LOG_DROP
#
# TCP packets with SYN,FIN flag set. SYN and FIN are both set.
$IPT -A INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j LOG_DROP
#
# SYN and RST are both set.
$IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j LOG_DROP
#
# FIN and RST are both set.
$IPT -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j LOG_DROP
#
# FIN is the only bit set, without the expected accompanying ACK.
$IPT -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j LOG_DROP
#
# PSH is the only bit set, without the expected accompanying ACK.
$IPT -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP
#
# URG is the only bit set, without the expected accompanying ACK.
$IPT -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP
#
# Null packets. All of the bits are cleared.
$IPT -A INPUT -p tcp -m tcp --tcp-flags ALL NONE -j LOG_DROP
#
#
# Log and drop spoofed packets pretending to be from the external interface's IP address.
$IPT -A INPUT -i $WAN_IF -s $WAN_IP -j LOG_DROP
#
# Log and drop packets claiming to be from a Class A private network
$IPT -A INPUT -i $WAN_IF -s $CLS_A -j LOG_DROP
#
# Log and drop packets claiming to be from a Class B private network
$IPT -A INPUT -i $WAN_IF -s $CLS_B -j LOG_DROP

# Log and drop packets claiming to be from a Class C private network
$IPT -A INPUT -i $WAN_IF -s $CLS_C -j LOG_DROP
#
# Log and drop packets claiming to be from the loopback interface
$IPT -A INPUT -i $WAN_IF -s $LPB_IF -j LOG_DROP
#
# Log and drop malformed broadcast packets.
$IPT -A INPUT -i $WAN_IF -s $BCST_DEST -j LOG_DROP
$IPT -A INPUT -i $WAN_IF -d $BCST_SRC  -j LOG_DROP
#
# Log and drop limited broadcasts.
$IPT -A INPUT -i $WAN_IF -d $BCST_DEST -j LOG_DROP
#
# Log and drop directed broadcasts.
# Used to map networks and in Denial of Service attacks
$IPT -A INPUT -i $WAN_IF -d $WAN_SN -j LOG_DROP
$IPT -A INPUT -i $WAN_IF -d $WAN_BR -j LOG_DROP
#
# Log and drop Class D multicast addresses.
# Illegal as a source address.
$IPT -A INPUT -i $WAN_IF -s $CLS_D_MLTCST -j LOG_DROP
#
# The next rule denies multicast packets carrying a non-UDP protocol
$IPT -A INPUT -i $WAN_IF ! -p udp -d $CLS_D_MLTCST -j LOG_DROP
$IPT -A INPUT -i $WAN_IF   -p udp -d $CLS_D_MLTCST -j ACCEPT
#
# Log and drop Class E reserved IP addresses
$IPT -A INPUT -i $WAN_IF -s $CLS_E_RESNET -j LOG_DROP
#
# Can't be blocked unilaterally with DHCP.
$IPT -A INPUT -i $WAN_IF -s $BCST_SRC_NET -j LOG_DROP
#
# Link Local Network..
$IPT -A INPUT -i $WAN_IF -s $LINK_LCL -j LOG_DROP
#
# TEST-NET.
$IPT -A INPUT -i $WAN_IF -s $TEST_NET -j LOG_DROP
#
# Silent Drop External Windows Clients Broadcast Traffic.
$IPT -A INPUT -p UDP -i $WAN_IF -d $WAN_BR --destination-port 135:139 -j DROP
#
# If we get DHCP requests from the Outside of our network, our logs will
# be swamped as well. This rule will block them from getting logged.
$IPT -A INPUT -p UDP -i $WAN_IF -d $BCST_DEST --destination-port 67:68 -j DROP

########################################################################
# Unlimited traffic on the loopback interface.
# Relax Rules to avoid excess traffic logging.
# We intend that Border Bastion Host don't have any services on it.
#
$IPT -A INPUT  -p ALL -s $LPB_SN -i $LPB_IF -j ACCEPT
$IPT -A OUTPUT -p ALL -d $LPB_SN -o $LPB_IF -j ACCEPT
#
$IPT -A INPUT  -p ALL -s $INT_IP -i $LPB_IF -j ACCEPT
$IPT -A INPUT  -p ALL -s $DMZ_IP -i $LPB_IF -j ACCEPT
#
$IPT -A INPUT  -p ALL -i $INT_IF -d $INT_IP -j ACCEPT
$IPT -A INPUT  -p ALL -i $DMZ_IF -d $DMZ_IP -j ACCEPT
#

#
# Drop and Log any packets that interal by default.
# X Window connection establishment
$IPT -A OUTPUT -o $WAN_IF -p tcp --syn --destination-port $XWINDOW_PORTS -j LOG_DROP
# X Window: incoming connection attempt
$IPT -A INPUT -i $WAN_IF -p tcp --syn --destination-port $XWINDOW_PORTS -j LOG_DROP
#
$IPT -A OUTPUT -o $WAN_IF -p tcp -m multiport --destination-port \
                  $NFS_PORT,$OPENWINDOWS_PORT,$SOCKS_PORT,$SQUID_PORT \
                  --syn -j LOG_DROP
#
$IPT -A INPUT -i $WAN_IF -p tcp -m multiport --destination-port \
                  $NFS_PORT,$OPENWINDOWS_PORT,$SOCKS_PORT,$SQUID_PORT \
                  --syn -j LOG_DROP

########################################################################
#
# Log and Accept packets with ESTABLISHED and RELATED flags.
# $IPT -A INPUT   -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT   -m state --state ESTABLISHED,RELATED -j LOGGING
$IPT -A LOGGING -m state --state ESTABLISHED,RELATED -j ACCEPT
# $IPT -A OUTPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT  -m state --state ESTABLISHED,RELATED -j LOGGING
$IPT -A LOGGING -m state --state ESTABLISHED,RELATED -j ACCEPT
# $IPT -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A FORWARD -m state --state ESTABLISHED,RELATED -j LOGGING
$IPT -A LOGGING -m state --state ESTABLISHED,RELATED -j ACCEPT
#



#$IPT -A INPUT -i $LAN_INTERFACE -p tcp -s $LAN_ADDRESSES --sport $UNPRIVPORTS \
#              -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#$IPT -A OUTPUT -o $LAN_INTERFACE \
#             -m state --state ESTABLISHED,RELATED -j ACCEPT


# FORWARD chain
# Drop bad packets
#
# Drop bad packets in FORWARD chain. Stealth Scans and TCP State Flags.
# Christmas tree packets
$IPT -A FORWARD -p tcp -m tcp --tcp-flags ALL FIN,PSH,URG -j LOG_DROP
#
# Invalid TCP packets
# New incoming TCP connection packets without SYN flag set
$IPT -A FORWARD -p tcp ! --syn -m state --state NEW -j LOG_DROP
#
# New state packet with SYN,ACK set
$IPT -A FORWARD -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j LOG_DROP
#
# TCP packets with SYN,FIN flag set. SYN and FIN are both set.
$IPT -A FORWARD -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j LOG_DROP
#
# SYN and RST are both set.
$IPT -A FORWARD -p tcp --tcp-flags SYN,RST SYN,RST -j LOG_DROP
#
# FIN and RST are both set.
$IPT -A FORWARD -p tcp --tcp-flags FIN,RST FIN,RST -j LOG_DROP
#
# FIN is the only bit set, without the expected accompanying ACK.
$IPT -A FORWARD -p tcp --tcp-flags ACK,FIN FIN -j LOG_DROP
#
# PSH is the only bit set, without the expected accompanying ACK.
$IPT -A FORWARD -p tcp --tcp-flags ACK,PSH PSH -j DROP
#
# URG is the only bit set, without the expected accompanying ACK.
$IPT -A FORWARD -p tcp --tcp-flags ACK,URG URG -j DROP
#
# Null packets. All of the bits are cleared.
$IPT -A FORWARD -p tcp -m tcp --tcp-flags ALL NONE -j LOG_DROP
#
# Drop spoofing packets coming on the WAN interface
iptables -A FORWARD -i $WAN_IF -s $LPB_SN -j LOG_DROP
iptables -A FORWARD -i $WAN_IF -s $CLS_A -j LOG_DROP
iptables -A FORWARD -i $WAN_IF -s $CLS_B -j LOG_DROP
iptables -A FORWARD -i $WAN_IF -s $CLS_C -j LOG_DROP
iptables -A FORWARD -i $WAN_IF -s $CLS_D_MLTCST -j LOG_DROP
iptables -A FORWARD -i $WAN_IF -s $CLS_E_RESNET -j LOG_DROP
iptables -A FORWARD -i $WAN_IF -s $BCST_SRC_NET -j LOG_DROP
iptables -A FORWARD -i $WAN_IF -s $LINK_LCL -j LOG_DROP
iptables -A FORWARD -i $WAN_IF -s $TEST_NET -j LOG_DROP
iptables -A FORWARD -i $WAN_IF -s $WAN_IP -j LOG_DROP

#
########################################################################
# INPUT chain close rules.
#
iptables -A INPUT -j LOG_DROP
#
# OUTPUT chain close rules.
iptables -A OUTPUT -j LOG_DROP
#
# FORWARD chain close rules.
iptables -A FORWARD -j LOG_DROP
#

# TEMPLATE for quick RULES
#$IPT -A INPUT -i $DMZ_IF -p tcp -s $DMZ_SN \
#              --sport $DYNC_PRTS --dport $RGST_PRTS \
#              -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#$IPT -A OUTPUT -o $DMZ_IF -d $DMZ_SN \
#             --dport $DYNC_PRTS --sport $DYNC_PRTS \
#             -m state --state ESTABLISHED,RELATED -j ACCEPT

