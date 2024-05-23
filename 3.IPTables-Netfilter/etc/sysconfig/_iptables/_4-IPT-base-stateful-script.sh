#!/bin/bash
########################################################################
# BORDER BASTION_HOST FIREWALL TEMPLATE
# with SNAT/DNAT and parameterization for easy and quick setup and rebase settings.
# Additional tuning and evolution I'll publish in this repo
# git@github.com:it-engineer-pro/FireWalling.git
########################################################################
# PROTECTED SUBNETWORKS PLANE:
#
# ISPNET_WAN:192.168.92.0/24 (WAN_IF)
# enp0s9/92.105
#
# DMZ_LAN:192.168.120.0/24 (DMZ_IF)
# enp0s8/120.10
#
# IDSSVS_LAN:192.168.110.0/24 (INT_IF)
# enp0s10/110.10
#
########################################################################

########################################################################
# Setup Base Network Parameters.
# For ALTLinux fix it in /etc/net/sysctl.conf
# For more info about these settings, look at:
# https://www.opennet.ru/docs/RUS/LARTC/x1727.html
# Enable IP forwarding1.
echo 1 > /proc/sys/net/ipv4/ip_forward
# /etc/net/sysctl.conf -- BaseALT with etc/net conig.
#
# Enable TCP SYN Cookie Protection.
#echo 1 > /proc/sys/net/ipv4/tcp_syncookies
#
# Enable broadcast echo Protection.
#echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
#
# Enable broadcast echo Protection.
#echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
#
# Disable Source Routed Packets.
#echo "0" > /proc/sys/net/ipv4/conf/all/accept_source_route
#
# Disable ICMP Redirect Acceptance.
#echo "0" > /proc/sys/net/ipv4/conf/all/accept_redirects
#
# Don't send Redirect Messages.
#echo "0" > /proc/sys/net/ipv4/conf/all/send_redirects
#
# Log packets with impossible addresses.
#echo "1" > /proc/sys/net/ipv4/conf/all/log_martians
#

#
# Drop Spoofed Packets coming in on an interface, which, if replied to,
# would result in the reply going out a different interface.
#for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
#    echo "1" > $f
#done
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
NEW="--ctstate NEW"                      #
NES="--ctstate NEW,ESTABLISHED"          #
NER="--ctstate NEW,ESTABLISHED,RELATED"  #
ESR="--ctstate ESTABLISHED,RELATED"      #
EST="--ctstate ESTABLISHED"              #
#LPB_IF="lo"                             # Local Network Interface. Not Acceptable Now.
                                         # Use lo
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
WTCP_PRTS="1:1024"                       # Well-known, privileged port range. TCP.
WUDP_PRTS="0:1024"                       # Well-known, privileged port range. UDP.
RGST_PRTS="105:49151"                   # Registered, privileged port range.
DYNC_PRTS="49152:65535"                  # Dynamic, unprivileged port range.
UNPR_PRTS="1025:65535"                   # Unprivileged port range.
#
WAN_IF="enp0s9"                          # External interface.
WAN_IPS="192.168.92.105/24"              # External IP address with SubNet.
WAN_SN="192.168.92.0/24"                 # External Subnet.
WAN_BR="192.168.92.255/24"               # External Subnet Broadcast.
WAN_IP="192.168.92.105"                  # External IP address/NoSN.
#
DMZ_IF="enp0s8"                          # DMZ interface.
DMZ_IPS="192.168.120.10/24"              # DMZ Interface IP address with SubNet..
DMZ_SN="192.168.120.0/24"                # DMZ Subnet.
DMZ_BR="192.168.120.255/24"              # DMZ Subnet Broadcast.
DMZ_IP="192.168.120.10"                  # DMZ Interface IP address/NoSN.
DMZ_RN="192.168.120.20-192.168.120.25"   # DMZ Interface IP addresses.
#
INT_IF="enp0s10"                         # Internal interface.
INT_IPS="192.168.110.10/24"              # Internal Interface IP address with SubNet..
INT_SN="192.168.110.0/24"                # Internal Subnet.
INT_BR="192.168.110.255/24"              # Internal Subnet Broadcast.
INT_IP="192.168.110.10"                  # Internal Interface IP address/NoSN.
INT_RN="192.168.110.11-192.168.110.12"   # INT GW IP addresses.
#
INT_GW_IP="192.168.110.11"               # Internal Interface IP address/NoSN.
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
#MY_ISP="my.isp.address.range"           # ISP server & NOC address range.
#DHCP_SRV="isp.dhcp.server"              # Address of your ISP dhcp server.
NS1="192.168.92.11"                      # Address of our local name server.
NS2="192.168.110.11"                     # Address of a remote name server.
POP_SRV="192.168.120.11"                 # Address of a remote pop server.
MAIL_SRV="192.168.120.11"                # Address of a remote mail gateway.
TIME_SRV="192.168.110.11"                # Address of a remote time server.
SSH_CLI1="192.168.192.100"               # Remote Support IP address.
SSH_LCLP="2220"                          # _LOCAL_SSHD_ port for remote
#                                        # support access.
SSH_STDP="22"                            # Standard SSH-Port.
SSH_DMZP="2221"                          # _DMZ_JH_ port for remote access
SSH_INTP="2222"                          # _INT_JH_ port for remote access
SSH_DMZsshIP="192.168.120.20"            # _DMZ_JH_ IP for remote access
SSH_INTsshIP="192.168.110.11"            # _INT_JH_ IP for remote access
#                                        # ALTerator access.
ATLS_STDP="8080"                         # Standard Alterator-Port.
ATLS_DMZP="8081"                         # _DMZ_JH_ port for remote access
ATLS_INTP="8082"                         # _INT_JH_ port for remote access


########################################################################

########################################################################
# Reset All Rules
########################################################################
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

########################################################################
# Default Policy Drop
#
$IPT -P INPUT DROP
$IPT -P FORWARD DROP
$IPT -P OUTPUT DROP
########################################################################

#
# LocalHost Allow
#
$IPT -A INPUT -i lo --source 127.0.0.1 --destination 127.0.0.1 -j ACCEPT

#
# Allow Est/Rel
#
$IPT -t filter -A INPUT -p tcp -m conntrack $ESR -j ACCEPT
$IPT -t filter -A OUTPUT -p tcp -m conntrack $ESR -j ACCEPT
$IPT -t filter -A FORWARD -p tcp -m conntrack $ESR -j ACCEPT

#
# Remote Control Rules (tcp/22 >> ssh/2220 external/DMZ port access)
# From Remote Support and Local DMZ JH Server
#
$IPT -A INPUT -s $SSH_CLI1 -p tcp --match multiport --sports $UNPR_PRTS -d $WAN_IP \
              --match multiport --dports $SSH_LCLP -m conntrack $NES -i $WAN_IF -j ACCEPT
$IPT -A OUTPUT -s $WAN_IP -p tcp --match multiport --sports $SSH_LCLP -d $SSH_CLI1 \
              --match multiport --dports $UNPR_PRTS -m conntrack $ESR  -o $WAN_IF -j ACCEPT
$IPT -A INPUT -s $SSH_DMZsshIP -p tcp --match multiport --sports $UNPR_PRTS -d $DMZ_IP \
              --match multiport --dports $SSH_LCLP -m conntrack $NES -i $DMZ_IF -j ACCEPT
$IPT -A OUTPUT -p tcp -s $DMZ_IP --match multiport --sports $SSH_LCLP -d $SSH_DMZsshIP \
               --match multiport --dports $UNPR_PRTS -m conntrack $ESR -o $DMZ_IF -j ACCEPT

#
# ICMP Out. Not tracing at all.
#
$IPT -A OUTPUT -p icmp --icmp-type echo-request -o $WAN_IF -m conntrack $NES -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type destination-unreachable -i $WAN_IF -m conntrack $ESR -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type time-exceeded -i $WAN_IF -m conntrack $ESR -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type echo-reply -i $WAN_IF -m conntrack $ESR -j ACCEPT

#
# ICMP Admin Host 1.
#
$IPT -A INPUT -s $SSH_CLI1 -p icmp --icmp-type echo-request -i $WAN_IF -d $WAN_IP -m conntrack $NES -j ACCEPT
$IPT -A OUTPUT -s $WAN_IP -p icmp --icmp-type destination-unreachable -o $WAN_IF -d $SSH_CLI1 -m conntrack $ESR -j ACCEPT
$IPT -A OUTPUT -s $WAN_IP -p icmp --icmp-type time-exceeded  -o $WAN_IF -d $SSH_CLI1 -m conntrack $ESR -j ACCEPT
$IPT -A OUTPUT -s $WAN_IP -p icmp --icmp-type echo-reply -o $WAN_IF -d $SSH_CLI1 -m conntrack $ESR -j ACCEPT


#
# ICMP Admin Host 2. Not tracing. Must be changed
#
$IPT -A INPUT -s $SSH_DMZsshIP -p icmp --icmp-type echo-request -i $DMZ_IF -d $DMZ_IP -m conntrack $NES -j ACCEPT
$IPT -A OUTPUT -s $DMZ_IP -p icmp --icmp-type destination-unreachable -o $DMZ_IF -d $SSH_DMZsshIP -m conntrack $ESR -j ACCEPT
$IPT -A OUTPUT -s $DMZ_IP -p icmp --icmp-type time-exceeded  -o $DMZ_IF -d $SSH_DMZsshIP -m conntrack $ESR -j ACCEPT
$IPT -A OUTPUT -s $DMZ_IP -p icmp --icmp-type echo-reply -o $DMZ_IF -d $SSH_DMZsshIP -m conntrack $ESR -j ACCEPT

#
# Access to external services from localhost (i.e. GW it-self)
# Usable for transform for GW or Server Services Publishing Rules.
#
$IPT -A OUTPUT -p udp -s $WAN_IP --match multiport --sports $UNPR_PRTS -d $NS1 \
               --match multiport --dports 53,123 -m conntrack $NES -o $WAN_IF -j ACCEPT
$IPT -A INPUT -p udp -s $NS1 --match multiport --sports 53,123 -d $WAN_IP \
              --match multiport --dports $UNPR_PRTS -m conntrack $ESR -i $WAN_IF -j ACCEPT
$IPT -A OUTPUT -p tcp -s $WAN_IP --match multiport --sports $UNPR_PRTS \
               --match multiport --dports 80,443 --syn -m conntrack $NEW -o $WAN_IF -j ACCEPT
$IPT -A OUTPUT -p tcp -s $WAN_IP --match multiport --sports $UNPR_PRTS \
               --match multiport --dports 80,443 -m conntrack $ESR -o $WAN_IF -j ACCEPT
$IPT -A INPUT -p tcp --match multiport --dports $UNPR_PRTS -d $WAN_IP \
              --match multiport --sports 80,443 -m conntrack $ESR -i $WAN_IF -j ACCEPT

#
# _SNAT Output Flow
# Should Be Tested with added -i $DMZ_IF for additional control.
# Should Be Tested with High source Ports From.
#
$IPT -t nat -A POSTROUTING -o $WAN_IF -s $DMZ_SN -p all -j SNAT --to $WAN_IP
$IPT -t nat -A POSTROUTING -o $WAN_IF -s $DMZ_SN -p icmp -j SNAT --to $WAN_IP
$IPT -t nat -A POSTROUTING -o $WAN_IF -s $INT_GW_IP -p all -j SNAT --to $WAN_IP
$IPT -t nat -A POSTROUTING -o $WAN_IF -s $INT_GW_IP -p icmp -j SNAT --to $WAN_IP

#
# _DNAT Input PinHoles
# SSH
#
$IPT -t nat -A PREROUTING -p tcp -i $WAN_IF -s $SSH_CLI1 -d $WAN_IP --dport $SSH_DMZP -j DNAT --to-destination $SSH_DMZsshIP:$SSH_STDP
$IPT -t nat -A PREROUTING -p tcp -i $WAN_IF -s $SSH_CLI1 -d $WAN_IP --dport $SSH_INTP -j DNAT --to-destination $INT_GW_IP:$SSH_STDP
# ALTerator
$IPT -t nat -A PREROUTING -p tcp -i $WAN_IF -s $SSH_CLI1 -d $WAN_IP --dport $ATLS_DMZP -j DNAT --to-destination $SSH_DMZsshIP:$ATLS_STDP
$IPT -t nat -A PREROUTING -p tcp -i $WAN_IF -s $SSH_CLI1 -d $WAN_IP --dport $ATLS_INTP -j DNAT --to-destination $INT_GW_IP:$ATLS_STDP
# FORWARDing for internal Host behind DNAT. Back Rules Relaing on rule iptables -t filter -A FORWARD -m conntrack $ESR -j ACCEPT
# If we want to control it more strictly, so we must write own back rule for back forwarding. It not works with -o.
$IPT -A FORWARD -p tcp -i $WAN_IF -s $SSH_CLI1 -m iprange --dst-range $DMZ_RN --match multiport --sports $UNPR_PRTS \
                --match multiport --dports $SSH_STDP,$SSH_LCLP,$SSH_DMZP,$ATLS_DMZP,5900,$ATLS_STDP \
                --syn -m conntrack $NEW -j ACCEPT
# Forwarding Rule For $ESR
$IPT -A FORWARD -p tcp -s $SSH_CLI1 -m iprange --dst-range $DMZ_RN --match multiport --sports $UNPR_PRTS \
                --match multiport --dports $SSH_STDP,$SSH_LCLP,$SSH_DMZP,$ATLS_DMZP,5900,$ATLS_STDP \
                -m conntrack $ESR -i $WAN_IF -o enp0e8 -j ACCEPT
# Forwarding SYN to Internal NAT Router.
$IPT -A FORWARD -p tcp -i $WAN_IF -s $SSH_CLI1 -m iprange --dst-range $INT_RN --match multiport --sports $UNPR_PRTS \
                --match multiport --dports $SSH_STDP,$SSH_INTP,$ATLS_INTP,5900,$ATLS_STDP --syn -m conntrack $NEW -j ACCEPT
$IPT -A FORWARD -p tcp -s $SSH_CLI1 -m iprange --dst-range $INT_RN --match multiport --sports $UNPR_PRTS \
                --match multiport --dports $SSH_STDP,$SSH_INTP,$ATLS_INTP,5900,$ATLS_STDP \
                -m conntrack $ESR -i $WAN_IF -o enp0e8 -j ACCEPT

#
# Test from JH to IntGW Host
#
$IPT -A FORWARD -i $DMZ_IF -o $INT_IF -s $SSH_DMZsshIP -d $INT_GW_IP \
                -p icmp --icmp-type echo-request -m conntrack $NES -j ACCEPT
$IPT -A FORWARD -i $INT_IF -o $DMZ_IF -s $INT_GW_IP -d $SSH_DMZsshIP \
                -p icmp --icmp-type destination-unreachable -m conntrack $ESR -j ACCEPT
$IPT -A FORWARD -i $INT_IF -o $DMZ_IF -s $INT_GW_IP -d $SSH_DMZsshIP \
                -p icmp --icmp-type time-exceeded -m conntrack $ESR -j ACCEPT
$IPT -A FORWARD -i $INT_IF -o $DMZ_IF -s $INT_GW_IP -d $SSH_DMZsshIP \
                -p icmp --icmp-type echo-reply -m conntrack $ESR -j ACCEPT
#
# Test Out from JH WAN Host
#
$IPT -A FORWARD -i $DMZ_IF -o $WAN_IF -s $SSH_DMZsshIP -p icmp --icmp-type echo-request -m conntrack $NES -j ACCEPT
$IPT -A FORWARD -i $WAN_IF -o $DMZ_IF -d $SSH_DMZsshIP -p icmp --icmp-type destination-unreachable -m conntrack $ESR -j ACCEPT
$IPT -A FORWARD -i $WAN_IF -o $DMZ_IF -d $SSH_DMZsshIP -p icmp --icmp-type time-exceeded -m conntrack $ESR -j ACCEPT
$IPT -A FORWARD -i $WAN_IF -o $DMZ_IF -d $SSH_DMZsshIP -p icmp --icmp-type echo-reply -m conntrack $ESR -j ACCEPT

#
# DMZ Segment Servers Forwarding Rules To Other WAN Servers.
# www/tls
$IPT -A FORWARD -p tcp -i $DMZ_IF -o $WAN_IF -s $DMZ_SN -m iprange --src-range $DMZ_RN \
                --match multiport --sports $UNPR_PRTS --match multiport --dports 443,80 \
                --syn -m conntrack $NEW -j ACCEPT
$IPT -A FORWARD -p tcp -i $DMZ_IF -o $WAN_IF -s $DMZ_SN -m iprange --src-range $DMZ_RN --match multiport --sports $UNPR_PRTS \
                --match multiport --dports 443,80 -m conntrack $ESR -j ACCEPT
$IPT -A FORWARD -p tcp -i $WAN_IF -o $DMZ_IF --match multiport --sports 443,80 -d $DMZ_SN -m iprange --dst-range $DMZ_RN \
                --match multiport --dports $UNPR_PRTS -m conntrack $ESR -j ACCEPT
# DNSqw/NTPqw
$IPT -A FORWARD -p udp -i $DMZ_IF -o $WAN_IF -m iprange --src-range $DMZ_RN --match multiport --sports $UNPR_PRTS -d $NS1 \
                --match multiport --dports 53,123 -m conntrack $NER -j ACCEPT
$IPT -A FORWARD -p udp -i $WAN_IF -o $DMZ_IF -s $NS1 --match multiport --sports 53,123 -m iprange --dst-range $DMZ_RN \
                --match multiport --dports $UNPR_PRTS -m conntrack $ESR -j ACCEPT

#
# Iternal Segment GWs Forwarding Rules To Other WAN Servers.
#
$IPT -A FORWARD -p tcp -i $INT_IF -o $WAN_IF -s $INT_GW_IP --match multiport --sports $UNPR_PRTS \
                --match multiport --dports 443,80 --syn -m conntrack $NEW -j ACCEPT
$IPT -A FORWARD -p tcp -i $INT_IF -o $WAN_IF -s $INT_GW_IP --match multiport --sports $UNPR_PRTS \
                --match multiport --dports 443,80 -m conntrack $ESR -j ACCEPT
$IPT -A FORWARD -p tcp -i $WAN_IF -o $INT_IF --match multiport --sports 443,80 -d $INT_GW_IP \
                --match multiport --dports $UNPR_PRTS -m conntrack $ESR -j ACCEPT
$IPT -A FORWARD -p udp -i $INT_IF -o $WAN_IF -s $INT_GW_IP --match multiport --sports $UNPR_PRTS \
                --match multiport -d $NS1 --dports 53,123 -m conntrack $NER -j ACCEPT
$IPT -A FORWARD -p udp -i $WAN_IF -o $INT_IF -s $NS1 --match multiport --sports 53,123  -d $INT_GW_IP \
                --match multiport --dports $UNPR_PRTS -m conntrack $NER -j ACCEPT

#
# Logging Policies
# Don't use DROP at end ?
$IPT -N LOGGING
$IPT -A OUTPUT -j LOGGING
$IPT -A FORWARD -j LOGGING
$IPT -A INPUT -j LOGGING
$IPT -A LOGGING -m limit --limit 60/min -j LOG --log-prefix "IPT-Logging: " --log-level 7
#$IPT -A LOGGING -j DROP
# journalctl -a | grep IPT ... etc

# User Defined Chains
# ...
