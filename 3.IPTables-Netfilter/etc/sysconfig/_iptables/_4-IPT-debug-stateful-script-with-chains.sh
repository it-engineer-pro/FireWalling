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
# Drop Spoofed Packets coming in on an interface, which, if replied to,
# would result in the reply going out a different interface.
#for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
#    echo "1" > $f
#done
########################################################################
# Additional kernel modules loading examples:
#
# /sbin/modprobe ip_conntrack_ftp
# /sbin/modprobe ip_tables
# /sbin/modprobe iptable_nat
# /sbin/modprobe ip_nat_ftp
# /sbin/modprobe ip_conntrack
# /sbin/modprobe ip_conntrack_ftp
#
########################################################################
#
# Aliaces and shortcuts
#
CON_TRAC="1"                             # Not used, but statreful.
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


########################################################################
# Describe User Defined Chains.
#
# _LCL_PASS_  # -- LOCAL PASS CASE CHAIN.
# _LOG_PASS_  # -- LOG and PASS with some logging info.
# _ESR_PASS_  # -- ESTABLISHE,RELATED passing chain.
# _LOG_DROP_  # -- LOG and DROP with limited logging info.
# _FWD_IN_    # -- FORWARD IN to the VPN case.
# _FWD_OUT_   # -- FORWARD OUT CHAIN.
# _FWD_DMZ_   # -- FORWARD IN and OUT DMZ CHAIN.
# _WAN_IN_    # -- EXTERNAL traffic clearning chain.
# _WAN_OUT_   # -- FW itself traffic OUT CHAIN.
# _LAN_IN_    # -- INTERNAL TRAFFIC OUT to FW itself.
# _LAN_OUT_   # -- INTERNAL TRAFFIC OUT to WAN.
# _DMZ_IN_    # -- INTERNAL TRAFFIC OUT to DMZ subnet.
# _DMZ_OUT_   # -- DMZ SERVERS answer stateful traffic.
# _SRV_LOCAL_ # -- LOCAL SERVERs segment of VPN case case CHAIN.
# _WAN_ICMP_  # -- WAN ICMP processing.
# _WAN_TRCR_  # -- WAN Traceroute diagnostic processing.
# _WAN_SSH_   # -- WAN SSH in and out processing.
# _WAN_WWW_   # -- WAN WWW in and processing and SQUID out traffic.
# _LAN_ICMP_  # -- Internal interfaces ICMP diagnostical traffic proc.
# _DMZ_TRCR_  # -- DMZ traceroute answers.
# _DMZ_ICMP_  # -- DMZ ping answers.

USER_CHAINS="_LCL_PASS_ _LOG_PASS_ _ESR_PASS_ _LOG_DROP_ "
# \
#            _FWD_IN_ _FWD_OUT_ _FWD_DMZ_ _WAN_IN_ _WAN_OUT_ \
#            _LAN_IN_ _LAN_OUT_ _DMZ_IN_ _DMZ_OUT_ \
#            _SRV_LOCAL_ _WAN_ICMP_ _WAN_TRCR_ _WAN_SSH_ _WAN_WWW_ \
#            _LAN_ICMP_ \
#            _DMZ_TRCR_ \
#            _DMZ_ICMP_ "
#
########################################################################
# Create the user-defined chains. See short descriptions.
#
for i in $USER_CHAINS; do
    $IPT -N $i
done
#

########################################################################
# LocalHost Allow
#
$IPT -A INPUT -i lo --source 127.0.0.1 --destination 127.0.0.1 -j ACCEPT
#
# Relax Rules to avoid excess traffic logging.
# We intend that Border Bastion Host don't have any services on it.
# _LCL_PASS_
#$IPT -A INPUT  -p ALL -i lo -s $LPB_SN -d $LPB_SN -j _LCL_PASS_
#$IPT -A OUTPUT -p ALL -o lo -s $LPB_SN -d $LPB_SN -j _LCL_PASS_
#
#$IPT -A INPUT  -p ALL -i lo -s $INT_IP -d $LPB_SN -j _LCL_PASS_
#$IPT -A INPUT  -p ALL -i lo -s $DMZ_IP -d $LPB_SN -j _LCL_PASS_
#
#$IPT -A INPUT  -p ALL -i $INT_IF -s $INT_IP -d $INT_IP -j _LCL_PASS_
#$IPT -A INPUT  -p ALL -i $DMZ_IF -s $DMZ_IP -d $DMZ_IP -j _LCL_PASS_
#
#$IPT -A _LCL_PASS_ -j ACCEPT
#$IPT -A _LCL_PASS_ -j DROP
########################################################################
#
# Allow Est/Rel (Logging for debug steps, and should be disabled).
#
$IPT -t filter -A INPUT -p tcp -m conntrack $ESR -j ACCEPT
$IPT -t filter -A OUTPUT -p tcp -m conntrack $ESR -j ACCEPT
$IPT -t filter -A FORWARD -p tcp -m conntrack $ESR -j ACCEPT
#$IPT -t filter -A INPUT -i $WAN_IF -m conntrack $ESR -j _ESR_PASS_
#$IPT -t filter -A INPUT -i $DMZ_IF -s $DMZ_SN -m conntrack $ESR -j _ESR_PASS_
#$IPT -t filter -A INPUT -i $INT_IF -s $INT_SN -m conntrack $ESR -j _ESR_PASS_
#$IPT -t filter -A OUTPUT -m conntrack $ESR -j _ESR_PASS_
#$IPT -t filter -A FORWARD -i $WAN_IF -o $DMZ_IF -m conntrack $ESR -j _ESR_PASS_
#$IPT -t filter -A FORWARD -i $WAN_IF -o $INT_IF -m conntrack $ESR -j _ESR_PASS_
#$IPT -t filter -A FORWARD -i $INT_IF -o $WAN_IF -s $INT_SN -m conntrack $ESR -j _ESR_PASS_
#$IPT -t filter -A FORWARD -i $INT_IF -o $DMZ_IF -s $INT_SN -d $DMZ_SN -m conntrack $ESR -j _ESR_PASS_
#$IPT -t filter -A FORWARD -i $DMZ_IF -o $WAN_IF -s $DMZ_SN -m conntrack $ESR -j _ESR_PASS_
#$IPT -t filter -A FORWARD -i $DMZ_IF -o $INT_IF -s $DMZ_SN -d $INT_SN -m conntrack $ESR -j _ESR_PASS_
#$IPT -A _ESR_PASS_ -m limit --limit 1800/min -j LOG --log-prefix "IPT-ESRPass: " --log-level 4
#$IPT -A _ESR_PASS_ -j ACCEPT
#
########################################################################

########################################################################
# Rules for cleaning traffic.
########################################################################
#$IPT -A INPUT  -m state --state INVALID -j LOG --log-prefix "IPT-LogINVALID-input: "
#$IPT -A INPUT  -m state --state INVALID -j DROP
#$IPT -A OUTPUT -m state --state INVALID -j LOG --log-prefix "IPT-LogINVALID-output: "
#$IPT -A OUTPUT -m state --state INVALID -j DROP
#$IPT -A FORWARD -m state --state INVALID -j LOG --log-prefix "IPT-LogINVALID-forward: "
#$IPT -A FORWARD -m state --state INVALID -j DROP

#
# Drop bad packets in INPUT chain. Stealth Scans and TCP State Flags.
# Christmas tree packets
#$IPT -A INPUT -p tcp -m tcp --tcp-flags ALL FIN,PSH,URG -j _LOG_DROP_
#
# Invalid TCP packets
# New incoming TCP connection packets without SYN flag set
#$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j _LOG_DROP_
#
# New state packet with SYN,ACK set
#$IPT -A INPUT -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j _LOG_DROP_
#
# TCP packets with SYN,FIN flag set. SYN and FIN are both set.
#$IPT -A INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j _LOG_DROP_
#
# SYN and RST are both set.
#$IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j _LOG_DROP_
#
# FIN and RST are both set.
#$IPT -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j _LOG_DROP_
#
# FIN is the only bit set, without the expected accompanying ACK.
#$IPT -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j _LOG_DROP_
#
# PSH is the only bit set, without the expected accompanying ACK.
#$IPT -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP
#
# URG is the only bit set, without the expected accompanying ACK.
#$IPT -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP
#
# Null packets. All of the bits are cleared.
#$IPT -A INPUT -p tcp -m tcp --tcp-flags ALL NONE -j _LOG_DROP_
#
# Log and drop spoofed packets pretending to be from the external interface's IP address.
#$IPT -A INPUT -i $WAN_IF -s $WAN_IP -j _LOG_DROP_
#
# Log and drop packets claiming to be from a Class A private network
#$IPT -A INPUT -i $WAN_IF -s $CLS_A -j _LOG_DROP_
#
# Log and drop packets claiming to be from a Class B private network
#$IPT -A INPUT -i $WAN_IF -s $CLS_B -j _LOG_DROP_

# Log and drop packets claiming to be from a Class C private network
#$IPT -A INPUT -i $WAN_IF -s $CLS_C -j _LOG_DROP_
#
# Log and drop packets claiming to be from the loopback interface
#$IPT -A INPUT -i $WAN_IF -s $LPB_SN -j _LOG_DROP_
#
# Log and drop malformed broadcast packets.
#$IPT -A INPUT -i $WAN_IF -s $BCST_DEST -j _LOG_DROP_
#$IPT -A INPUT -i $WAN_IF -d $BCST_SRC -j _LOG_DROP_
#
# Log and drop limited broadcasts.
#$IPT -A INPUT -i $WAN_IF -d $BCST_DEST -j _LOG_DROP_
#
# Log and drop directed broadcasts.
# Used to map networks and in Denial of Service attacks
#$IPT -A INPUT -i $WAN_IF -d $WAN_SN -j _LOG_DROP_
#$IPT -A INPUT -i $WAN_IF -d $WAN_BR -j _LOG_DROP_
#
# Log and drop Class D multicast addresses.
# Illegal as a source address.
#$IPT -A INPUT -i $WAN_IF -s $CLS_D_MLTCST -j _LOG_DROP_
#
# The next rule denies multicast packets carrying a non-UDP protocol
#$IPT -A INPUT -i $WAN_IF ! -p udp -d $CLS_D_MLTCST -j _LOG_DROP_
#$IPT -A INPUT -i $WAN_IF   -p udp -d $CLS_D_MLTCST -j ACCEPT
#
# Log and drop Class E reserved IP addresses
#$IPT -A INPUT -i $WAN_IF -s $CLS_E_RESNET -j _LOG_DROP_
#
# Can't be blocked unilaterally with DHCP.
#$IPT -A INPUT -i $WAN_IF -s $BCST_SRC_NET -j _LOG_DROP_
#
# Link Local Network..
#$IPT -A INPUT -i $WAN_IF -s $LINK_LCL -j _LOG_DROP_
#
# TEST-NET.
#$IPT -A INPUT -i $WAN_IF -s $TEST_NET -j _LOG_DROP_
#
# Silent Drop External Windows Clients Broadcast Traffic.
#$IPT -A INPUT -p UDP -i $WAN_IF -d $WAN_BR --destination-port 135:139 -j DROP
#
# If we get DHCP requests from the Outside of our network, our logs will
# be swamped as well. This rule will block them from getting logged.
#$IPT -A INPUT -p UDP -i $WAN_IF -d $BCST_DEST --destination-port 67:68 -j DROP

#
# Drop and Log any packets that interal by default.
# X Window connection establishment
#$IPT -A OUTPUT -o $WAN_IF -p tcp --syn --destination-port $XWINDOW_PORTS -j _LOG_DROP_
# X Window: incoming connection attempt
#$IPT -A INPUT -i $WAN_IF -p tcp --syn --destination-port $XWINDOW_PORTS -j _LOG_DROP_
#
#$IPT -A OUTPUT -o $WAN_IF -p tcp -m multiport --destination-port \
#                  $NFS_PORT,$OPENWINDOWS_PORT,$SOCKS_PORT,$SQUID_PORT \
#                  --syn -j _LOG_DROP_
#
#$IPT -A INPUT -i $WAN_IF -p tcp -m multiport --destination-port \
#                  $NFS_PORT,$OPENWINDOWS_PORT,$SOCKS_PORT,$SQUID_PORT \
#                  --syn -j _LOG_DROP_

########################################################################
# INPUT chain,  Drop Brutforsers.
#
#$IPT -A INPUT -p tcp -m multiport --dports $SSH_LCLP,$SSH_DMZP,$SSH_INTP,$SSH_STDP \
#                   -m recent --set --name SEC --syn -m state --state NEW -j _WAN_SSH_
#
#$IPT -A _WAN_SSH_ -p tcp -m multiport --dports $SSH_LCLP,$SSH_DMZP,$SSH_INTP,$SSH_STDP \
#                  -m recent --update --seconds 60 --hitcount 2 \
#                  --rttl --name SEC -j LOG --log-prefix "BRUTE FORCE "
#
#$IPT -A _WAN_SSH_ -p tcp -m multiport --dports $SSH_LCLP,$SSH_DMZP,$SSH_INTP,$SSH_STDP \
#                  -m recent --update --seconds 60 --hitcount 2 --rttl --name SEC -j _LOG_DROP_

#
# Remote Control Rules (tcp/22 >> ssh/2220 external/DMZ port access)
# From Remote Support and Local DMZ JH Server
#
$IPT -A INPUT -s $SSH_CLI1 -p tcp --match multiport --sports $UNPR_PRTS -d $WAN_IP \
              --match multiport --dports $SSH_LCLP --syn -m conntrack $NEW -i $WAN_IF -j ACCEPT
$IPT -A INPUT -s $SSH_CLI1 -p tcp --match multiport --sports $UNPR_PRTS -d $WAN_IP \
              --match multiport --dports $SSH_LCLP -m conntrack $ESR -i $WAN_IF -j ACCEPT
$IPT -A OUTPUT -s $WAN_IP -p tcp --match multiport --sports $SSH_LCLP -d $SSH_CLI1 \
              --match multiport --dports $UNPR_PRTS -m conntrack $ESR  -o $WAN_IF -j ACCEPT
$IPT -A INPUT -s $SSH_DMZsshIP -p tcp --match multiport --sports $UNPR_PRTS -d $DMZ_IP \
              --match multiport --dports $SSH_LCLP --syn -m conntrack $NEW -i $DMZ_IF -j ACCEPT
$IPT -A INPUT -s $SSH_DMZsshIP -p tcp --match multiport --sports $UNPR_PRTS -d $DMZ_IP \
              --match multiport --dports $SSH_LCLP -m conntrack $ESR -i $DMZ_IF -j ACCEPT
$IPT -A OUTPUT -p tcp -s $DMZ_IP --match multiport --sports $SSH_LCLP -d $SSH_DMZsshIP \
               --match multiport --dports $UNPR_PRTS -m conntrack $ESR -o $DMZ_IF -j ACCEPT


$IPT -A INPUT -p icmp --icmp-type echo-reply -m limit --limit \
              60/minute --limit-burst 5 -j DROP
$IPT -A INPUT -m limit --limit 60/minute --limit-burst 3 -j LOG \
              --log-level DEBUG --log-prefix "IPT-INPUT-packet-died: "

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
#
# SSH
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
$IPT -A LOGGING -m limit --limit 600/min -j LOG --log-prefix "IPT-Logging: " --log-level 7

# journalctl -a | grep IPT ... etc

# User Defined Chains
# ...
########################################################################
# Define custom chain LOGGING for diagnostic and control.
# Packets with higher then limit will be rejected
# when not redirected to other chains.
#


#

# TEMPLATE for quick RULES.
#$IPT -A INPUT -i $DMZ_IF -p tcp -s $DMZ_SN \
#              --sport $DYNC_PRTS --dport $RGST_PRTS \
#              -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#$IPT -A OUTPUT -o $DMZ_IF -d $DMZ_SN \
#             --dport $DYNC_PRTS --sport $DYNC_PRTS \
#             -m state --state ESTABLISHED,RELATED -j ACCEPT
########################################################################
# Define custom chain _LOG_DROP_ for log dropped packets.
#
#$IPT -A _LOG_DROP_ -m limit --limit 10/min -j LOG --log-prefix "IPT-LogDrop: " --log-level 7
#$IPT -A _LOG_DROP_ -j DROP
#$IPT -A LOGGING -j REJECT
