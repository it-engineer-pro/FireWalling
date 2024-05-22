#!/bin/bash
########################################################################
# BORDER BASTION_HOST FIREWALL TEMPLATE
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
# Enable IP forwarding1.
echo 1 > /proc/sys/net/ipv4/ip_forward
#
# Enable TCP SYN Cookie Protection.
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
#
# Enable broadcast echo Protection.
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
#
# Disable Source Routed Packets.
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
#
# Disable ICMP Redirect Acceptance.
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
#
# Don't send Redirect Messages.
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
#
# Log packets with impossible addresses.
echo 1 > /proc/sys/net/ipv4/conf/all/log_martians
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
WTCP_PRTS="1:1023"                       # Well-known, privileged port range. TCP.
WUDP_PRTS="0:1023"                       # Well-known, privileged port range. UDP.
RGST_PRTS="1023:49151"                   # Registered, privileged port range.
DYNC_PRTS="49152:65535"                  # Dynamic, unprivileged port range.
UNPR_PRTS="1024:65535"                   # Unprivileged port range.
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
#
INT_IF="enp0s10"                         # Internal interface.
INT_IPS="192.168.110.10/24"              # Internal Interface IP address with SubNet..
INT_SN="192.168.110.0/24"                # Internal Subnet.
INT_BR="192.168.110.255/24"              # Internal Subnet Broadcast.
INT_IP="192.168.110.10"                  # Internal Interface IP address/NoSN.
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
NS1="192.168.120.15"                     # Address of a local name server.
NS2="192.168.110.11"                     # Address of a remote name server.
POP_SRV="192.168.120.11"                 # Address of a remote pop server.
MAIL_SRV="192.168.120.11"                # Address of a remote mail gateway.
TIME_SRV="192.168.110.11"                # Address of a remote time server.
SSH_CLI1="192.168.192.100"               # Remote Support IP address.
SSH_LCLP="2220"                          # _LOCAL_SSHD_ port for remote
                                         # support access.
SSH_STDP="22"                            # Standard SSH-Port.
SSH_DMZP="2221"                          # _DMZ_JH_ port for remote access
SSH_INTP="2222"                          # _INT_JH_ port for remote access
SSH_DMZsshIP="192.168.120.20"            # _DMZ_JH_ IP for remote access
SSH_INTsshIP="192.168.110.11"            # _INT_JH_ IP for remote access

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
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP
#

# Allow Est/Rel
$IPT -t filter -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IPT -t filter -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IPT -t filter -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

#
# Some Basic Logging and Protection
# "IPT-Drop: "
# New Packets Logging
#$IPT -A INPUT -m state --state NEW -j LOG --log-level 4 --log-prefix="IPT-New: Input "
#$IPT -A FORWARD -m state --state NEW -j LOG --log-level 4 --log-prefix="IPT-New: Forward "
#$IPT -A OUTPUT -m state --state NEW -j LOG --log-level 4 --log-prefix="IPT-New: Out "
#


########################################################################
# Remote SSH and ICMP/Traceroute Support for setup and debug rules.
# Whitelisted SSH-IN/PING/TRACEROUTE from/to(P/T) SUPPORT. 
# Case ! <<-i $WAN_IF -d $WAN_IP>> == it's a same and
# Case ! <<-o $WAN_IF -s $WAN_IP>> == it's a same
#
#$IPT -A INPUT  -p tcp -s $SSH_CLI1 -i $WAN_IF  -d $WAN_IP \
#               --sport $UNPR_PRTS \
#               -m multiport --dports $SSH_LCLP,$SSH_DMZP,$SSH_INTP,$SSH_STDP \
#               -m conntrack --ctstate NEW -j ACCEPT
#
#$IPT -A OUTPUT -p tcp -o $WAN_IF -s $WAN_IP -d $SSH_CLI1 \
#               --dport $UNPR_PRTS \
#               -m multiport --sports $SSH_LCLP,$SSH_DMZP,$SSH_INTP,$SSH_STDP \
#               -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# ICMP IN and OUT to SUPPORT.
#$IPT -A INPUT  -p icmp --icmp-type echo-request \
#               -s $SSH_CLI1 -i $WAN_IF -d $WAN_IP \
#               -m conntrack --ctstate NEW -j ACCEPT
#
#$IPT -A OUTPUT -p icmp --icmp-type echo-reply \
#               -d $SSH_CLI1 -o $WAN_IF -s $WAN_IP \
#               -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# ICMP OUT
#$IPT -A OUTPUT -p icmp --icmp-type echo-request \
#               -d $SSH_CLI1 -o $WAN_IF -s $WAN_IP \
#               -m conntrack --ctstate NEW -j ACCEPT
#
#$IPT -A INPUT  -p icmp --icmp-type echo-reply \
#               -s $SSH_CLI1 -i $WAN_IF -d $WAN_IP \
#               -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# TRACEROTE IN and OUT to SUPPORT.
$IPT -A INPUT  -p udp --dport 33434:33524 \
               -s $SSH_CLI1 -i $WAN_IF -d $WAN_IP \
               -m conntrack --ctstate NEW -j ACCEPT
#
$IPT -A OUTPUT -p udp --sport 33434:33524 \
               -d $SSH_CLI1 -o $WAN_IF -s $WAN_IP \
               -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# TRACEROUTE OUT
$IPT -A OUTPUT -p udp --dport 33434:33524 \
               -d $SSH_CLI1 -o $WAN_IF -s $WAN_IP \
               -m conntrack --ctstate NEW -j ACCEPT
#
$IPT -A INPUT  -p udp --sport 33434:33524 \
               -s $SSH_CLI1 -i $WAN_IF -d $WAN_IP \
               -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#

#
# LocalHost Remote Control Rules (tcp/22)
# FROM REMOTE SUPPORT IP
$IPT -A INPUT -p tcp -s 192.168.192.100 --sport 1025:65535 \
                     -d 192.168.92.105 --dport 2220 \
                     -m conntrack --ctstate NEW,ESTABLISHED \
                     -i enp0s9 -j ACCEPT
#
$IPT -A OUTPUT -p tcp -s 192.168.92.105 --sport 2220 \
               -d 192.168.192.100 --dport 1025:65535 \
               -m conntrack --ctstate ESTABLISHED \
               -o enp0s9 -j ACCEPT
# FROM DJHOST in DMZ
$IPT -A INPUT -p tcp -s 192.168.120.20 --sport 1025:65535 \
              -d 192.168.120.10 --dport 2220 \
              -m conntrack --ctstate NEW,ESTABLISHED \
              -i enp0s8 -j ACCEPT
#
$IPT -A OUTPUT -p tcp -s 192.168.120.10 --sport 2220 \
               -d 192.168.120.20 --dport 1025:65535 \
               -m conntrack --ctstate ESTABLISHED \
               -o enp0s8 -j ACCEPT

########################################################################
#
# ICMP LocalHost Policies
#
# ICMP Out. Not tracing at all, No ICMP in.
#
$IPT -A OUTPUT -p icmp --icmp-type echo-request \
               -o enp0s9 -m conntrack --ctstate NEW -j ACCEPT
#
$IPT -A INPUT -p icmp --icmp-type destination-unreachable \
              -i enp0s9 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#
$IPT -A INPUT -p icmp --icmp-type time-exceeded \
              -i enp0s9 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#
$IPT -A INPUT -p icmp --icmp-type echo-reply \
              -i enp0s9 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#

#
# ICMP Admin Host 1
# ( External Lab Host 92.11 -- DGW,AP,DNS,NTP;
# 192.100 -- LapTop Address and MNgmntHost and NTPd Server;
# 192.188/24 -- RR EXT_IF_IP )
$IPT -A INPUT -s 192.168.192.100 -p icmp \
              --icmp-type echo-request -d 192.168.92.105 -i enp0s9 \
              -m conntrack --ctstate NEW -j ACCEPT
#
$IPT -A OUTPUT -s 192.168.92.105 -p icmp \
              --icmp-type destination-unreachable -d 192.168.192.100 \
              -o enp0s9 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#
$IPT -A OUTPUT -s 192.168.92.105 -p icmp \
              --icmp-type time-exceeded -d 192.168.192.100 \
              -o enp0s9 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#
$IPT -A OUTPUT -s 192.168.92.105 -p icmp \
              --icmp-type echo-reply -d 192.168.192.100 \
              -o enp0s9 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#
# ICMP Admin Host 2 ( SRV Range: 20-120; Admin Internal Addr: 20,100; Clients Range 120/20-120)
$IPT -A INPUT -s 192.168.120.20 -p icmp \
              --icmp-type echo-request -d 192.168.120.10 \
              -m conntrack --ctstate NEW -i enp0s8 -j ACCEPT
#
$IPT -A OUTPUT -s 192.168.120.10 -p icmp \
              --icmp-type destination-unreachable -d 192.168.120.20 \
              -o enp0s8 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#
$IPT -A OUTPUT -s 192.168.120.10 -p icmp \
              --icmp-type time-exceeded -d 192.168.120.20 \
              -o enp0s8 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#
$IPT -A OUTPUT -s 192.168.120.10 -p icmp \
              --icmp-type echo-reply -d 192.168.120.20 \
              -o enp0s8 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#
# Access to external services (DNS,NTPs,HTTP(repo),HTTPS(SSL-dl)), No SSH-Out from LocalHost.
# TCP
$IPT -A OUTPUT -p tcp -s 192.168.92.105 --sport 1025:65535 \
               --match multiport --dports 80,443 \
               -m conntrack --ctstate NEW,ESTABLISHED \
               -o enp0s9 -j ACCEPT
#
$IPT -A INPUT -p tcp -d 192.168.92.105/24 --dport 1025:65535 \
              --match multiport --sports 80,443 \
              -m conntrack --ctstate ESTABLISHED \
              -i enp0s9 -j ACCEPT
# UDP
$IPT -A OUTPUT -p udp -s 192.168.92.105 --sport 1025:65535 \
               --match multiport --dports 53,123 \
               -m conntrack --ctstate NEW,ESTABLISHED \
               -o enp0s9 -j ACCEPT
#
$IPT -A INPUT -p udp -d 192.168.92.105 --dport 1025:65535 \
              --match multiport --sports 53,123 \
              -m conntrack --ctstate ESTABLISHED \
              -i enp0s9 -j ACCEPT

########################################################################
# SNAT//DNAT
########################################################################
#  --match multiport --dports 25,465,995,993,443,80
$IPT -A INPUT -p tcp -i enp0e9 --sport 1025:65535 \
              --match multiport --dports 22,2220:2222 \
              --syn -m conntrack --ctstate NEW -j ACCEPT
#
$IPT -A FORWARD -p tcp -i enp0e9 --sport 1025:65535 \
                -o enp0e8 --dport 2221 \
                --syn -m conntrack --ctstate NEW \
                -j ACCEPT
#
$IPT -A FORWARD -p tcp -i enp0e9 -o enp0e10 --sport 1025:65535 \
                --dport 2222 --syn -m conntrack --ctstate NEW -j ACCEPT
#
# Allow Packet Flow In
$IPT -A FORWARD -p tcp -i enp0s9 -o enp0s8 --sport 1025:65535 --dport 2221 \
                -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#
$IPT -A FORWARD -p tcp -i enp0s9 -o enp0s10 --sport 1025:65535 --dport 2222 \
                -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#
# Allow Packet Flow Out
$IPT -A FORWARD -p tcp -i enp0s8 -o enp0s9 --sport 2221 --dport 1025:65535 \
                -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#
$IPT -A FORWARD -p tcp -i enp0s10 -o enp0s9 --sport 2222 --dport 1025:65535 \
                -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

########################################################################
# Then in Table NAT in PREROUTING in EXTIF make pinhole on port and
# DNAT Jump to destination to internal IP and Port
# iptables -t nat -A PREROUTING -i enp0e9 -p tcp \
#          --dport 80 -j DNAT --to-destination 10.0.0.1:80
########################################################################
# ssl
# vnc
#iptables -t nat -A PREROUTING  -i enp0e3 -s 192.168.111.220 -d 192.168.111.130 -p tcp \
#--dport 5913 -j DNAT --to-destination 192.168.50.13:5900
# rdp
# ssh
$IPT -t nat -A PREROUTING -i enp0e9 -s 192.168.192.100 \
            -d 192.168.92.105 -p tcp --dport 2221 -j DNAT \
            --to-destination 192.168.120.20:2221
                                                      # to REDOS1
#
$IPT -t nat -A PREROUTING -i enp0e9 -s 192.168.192.100 \
            -d 192.168.92.105 -p tcp --dport 2222 -j DNAT \
            --to-destination 192.168.110.11:2222
                                                      # to REDOS3

########################################################################
# POSTROUTING / SNAT.
# Must be enabled for normal pin-holes functions
########################################################################
## ssh/POSTROUTING
#iptables -t nat -A POSTROUTING -o enp0s3 \
#         -s 192.168.10.11 -p tcp --dport 8080 -j SNAT \
#         --to 192.168.111.130:8011
# TCP/2221
$IPT -t nat -A POSTROUTING -o enp0s9 \
         -s 192.168.120.20 -p tcp --dport 2221 -j SNAT \
         --to 192.168.92.105:2221
# TCP/2222
$IPT -t nat -A POSTROUTING -o enp0s9 \
         -s 192.168.110.11 -p tcp --dport 2222 -j SNAT \
         --to 192.168.92.105:2222
#
#
# SNAT ICMP Output Flow
#
# from DMZ_LAN
$IPT -t nat -A POSTROUTING -o enp0s9 -s 192.168.120.0/24 -p icmp \
            -j SNAT --to 192.168.92.105
# from INT_LAN
$IPT -t nat -A POSTROUTING -o enp0s9 -s 192.168.110.0/24 -p icmp \
            -j SNAT --to 192.168.92.105

# SNAT for DMZ_Chain -N 120.0/24
$IPT -t nat -A POSTROUTING -o enp0s9 -s 192.168.120.0/24 -p tcp \
            -j SNAT --to 192.168.92.105
$IPT -t nat -A POSTROUTING -o enp0s9 -s 192.168.120.0/24 -p udp \
            -j SNAT --to 192.168.92.105

# SNAT for INT_Chain -N 110.11/24
$IPT -t nat -A POSTROUTING -o enp0s9 -s 192.168.110.0/24 -p tcp \
            -j SNAT --to 192.168.92.105
$IPT -t nat -A POSTROUTING -o enp0s9 -s 192.168.110.0/24 -p udp \
            -j SNAT --to 192.168.92.105

# Forwarding Rules for DMZ ZONE (Admin Host Local Diag)
# In to INT_LAN
$IPT -A FORWARD -s 192.168.120.20 -d 192.168.110.11 -p icmp --icmp-type echo-request -j ACCEPT
$IPT -A FORWARD -s 192.168.110.11 -d 192.168.120.20 -p icmp --icmp-type destination-unreachable -j ACCEPT
$IPT -A FORWARD -s 192.168.110.11 -d 192.168.120.20 -p icmp --icmp-type time-exceeded -j ACCEPT
$IPT -A FORWARD -s 192.168.110.11 -d 192.168.120.20 -p icmp --icmp-type echo-reply -j ACCEPT
# In DMZ
$IPT -A FORWARD -s 192.168.110.11 -d 192.168.120.20/24 -p icmp --icmp-type echo-request -j ACCEPT
$IPT -A FORWARD -s 192.168.120.20/24 -d 192.168.110.11 -p icmp --icmp-type destination-unreachable -j ACCEPT
$IPT -A FORWARD -s 192.168.120.20/24 -d 192.168.110.11 -p icmp --icmp-type time-exceeded -j ACCEPT
$IPT -A FORWARD -s 192.168.120.20/24 -d 192.168.110.11 -p icmp --icmp-type echo-reply -j ACCEPT
# Out to Inet from DMZ
$IPT -A FORWARD -s 192.168.120.0/24 -o enp0s9 \
                -p icmp --icmp-type echo-request \
                -m conntrack --ctstate NEW -j ACCEPT
#
$IPT -A FORWARD -i enp0s9 -p icmp --icmp-type destination-unreachable \
                -m conntrack --ctstate ESTABLISHED -j ACCEPT
#
$IPT -A FORWARD -i enp0s9 -p icmp --icmp-type time-exceeded \
                -m conntrack --ctstate ESTABLISHED -j ACCEPT
#
$IPT -A FORWARD -i enp0s9 -p icmp --icmp-type echo-reply \
                -m conntrack --ctstate ESTABLISHED -j ACCEPT
#
# Out to Inet from INT_GW
$IPT -A FORWARD -s 192.168.110.11 -o enp0s9 \
                -p icmp --icmp-type echo-request \
                -m conntrack --ctstate NEW -j ACCEPT
#
$IPT -A FORWARD -i enp0s9 -p icmp --icmp-type destination-unreachable \
                -m conntrack --ctstate ESTABLISHED -j ACCEPT
#
$IPT -A FORWARD -i enp0s9 -p icmp --icmp-type time-exceeded \
                -m conntrack --ctstate ESTABLISHED -j ACCEPT
#
$IPT -A FORWARD -i enp0s9 -p icmp --icmp-type echo-reply \
                -m conntrack --ctstate ESTABLISHED -j ACCEPT


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

USER_CHAINS="_LCL_PASS_ _LOG_PASS_ _ESR_PASS_ _LOG_DROP_ \
            _FWD_IN_ _FWD_OUT_ _FWD_DMZ_ _WAN_IN_ _WAN_OUT_ \
            _LAN_IN_ _LAN_OUT_ _DMZ_IN_ _DMZ_OUT_ \
            _SRV_LOCAL_ _WAN_ICMP_ _WAN_TRCR_ _WAN_SSH_ _WAN_WWW_ \
            _LAN_ICMP_ \
            _DMZ_TRCR_ \
            _DMZ_ICMP_ \
            _TRAF_PROT_"
#
########################################################################
# Create the user-defined chains. See short descriptions.
#
for i in $USER_CHAINS; do
    $IPT -N $i
done
#

# Relax Rules to avoid excess traffic logging.
# We intend that Border Bastion Host don't have any services on it.
# _LCL_PASS_
$IPT -A INPUT -i lo --source 127.0.0.1 --destination 127.0.0.1 -j _LCL_PASS_
#
$IPT -A INPUT  -p ALL -i lo -s $LPB_SN -d $LPB_SN -j _LCL_PASS_
$IPT -A OUTPUT -p ALL -o lo -s $LPB_SN -d $LPB_SN -j _LCL_PASS_
#
$IPT -A INPUT  -p ALL -i lo -s $INT_IP -d $LPB_SN -j _LCL_PASS_
$IPT -A INPUT  -p ALL -i lo -s $DMZ_IP -d $LPB_SN -j _LCL_PASS_
#
$IPT -A INPUT  -p ALL -i $INT_IF -s $INT_IP -d $INT_IP -j _LCL_PASS_
$IPT -A INPUT  -p ALL -i $DMZ_IF -s $DMZ_IP -d $DMZ_IP -j _LCL_PASS_
#
$IPT -A _LCL_PASS_ -j ACCEPT
$IPT -A _LCL_PASS_ -j DROP
########################################################################
# Unlimited traffic on the loopback interface.
#
# LocalHost Allow
#
#$IPT -A INPUT -i lo --source 127.0.0.1 --destination 127.0.0.1 -j ACCEPT
#

########################################################################
# Define custom chain LOG_DROP for log dropped packets.
#
$IPT -A _LOG_DROP_ -m limit --limit 600/min -j LOG --log-prefix "IPT-LogDrop: " --log-level 7
$IPT -A _LOG_DROP_ -j DROP

########################################################################
# Rules for cleaning traffic.
#
#$IPT -A INPUT  -m state --state INVALID -j LOG --log-prefix "IPT-LogINVALID-input: "
#$IPT -A INPUT  -m state --state INVALID -j _TRAF_PROT_
#$IPT -A OUTPUT -m state --state INVALID -j LOG --log-prefix "IPT-LogINVALID-output: "
#$IPT -A OUTPUT -m state --state INVALID -j _TRAF_PROT_
#$IPT -A FORWARD -m state --state INVALID -j LOG --log-prefix "IPT-LogINVALID-input: "
#$IPT -A FORWARD -m state --state INVALID -j _TRAF_PROT_

#
# Drop bad packets in INPUT chain. Stealth Scans and TCP State Flags.
# Christmas tree packets
#$IPT -A INPUT -i $WAN_IF -p tcp -m tcp --tcp-flags ALL FIN,PSH,URG -j _TRAF_PROT_
#
# Invalid TCP packets
# New incoming TCP connection packets without SYN flag set
#$IPT -A INPUT -i $WAN_IF -p tcp ! --syn -m state --state NEW -j _TRAF_PROT_
#
# New state packet with SYN,ACK set
#$IPT -A INPUT -i $WAN_IF -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j _TRAF_PROT_
#
# TCP packets with SYN,FIN flag set. SYN and FIN are both set.
#$IPT -A INPUT -i $WAN_IF -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j _TRAF_PROT_
#
# SYN and RST are both set.
#$IPT -A INPUT -i $WAN_IF -p tcp --tcp-flags SYN,RST SYN,RST -j _TRAF_PROT_
#
# FIN and RST are both set.
#$IPT -A INPUT -i $WAN_IF -p tcp --tcp-flags FIN,RST FIN,RST -j _TRAF_PROT_
#
# FIN is the only bit set, without the expected accompanying ACK.
#$IPT -A INPUT -i $WAN_IF -p tcp --tcp-flags ACK,FIN FIN -j _TRAF_PROT_
#
# PSH is the only bit set, without the expected accompanying ACK.
#$IPT -A INPUT -i $WAN_IF -p tcp --tcp-flags ACK,PSH PSH -j _TRAF_PROT_
#
# URG is the only bit set, without the expected accompanying ACK.
#$IPT -A INPUT -i $WAN_IF -p tcp --tcp-flags ACK,URG URG -j _TRAF_PROT_
#
# Null packets. All of the bits are cleared.
#$IPT -A INPUT -i $WAN_IF -p tcp -m tcp --tcp-flags ALL NONE -j _TRAF_PROT_
#
# Log and drop spoofed packets pretending to be from the external interface's IP address.
#$IPT -A INPUT -i $WAN_IF -s $WAN_IP -j _TRAF_PROT_
#
# Log and drop packets claiming to be from a Class A private network
#$IPT -A INPUT -i $WAN_IF -s $CLS_A -j _TRAF_PROT_
#
# Log and drop packets claiming to be from a Class B private network
#$IPT -A INPUT -i $WAN_IF -s $CLS_B -j _TRAF_PROT_

# Log and drop packets claiming to be from a Class C private network
#$IPT -A INPUT -i $WAN_IF -s $CLS_C -j _TRAF_PROT_
#
# Log and drop packets claiming to be from the loopback interface
#$IPT -A INPUT -i $WAN_IF -s $LPB_SN -j _TRAF_PROT_
#
# Log and drop malformed broadcast packets.
#$IPT -A INPUT -i $WAN_IF -s $BCST_DEST -j _TRAF_PROT_
#$IPT -A INPUT -i $WAN_IF -d $BCST_SRC -j _TRAF_PROT_
#
# Log and drop limited broadcasts.
#$IPT -A INPUT -i $WAN_IF -d $BCST_DEST -j _TRAF_PROT_
#
# Log and drop directed broadcasts.
# Used to map networks and in Denial of Service attacks
#$IPT -A INPUT -i $WAN_IF -d $WAN_SN -j _TRAF_PROT_
#$IPT -A INPUT -i $WAN_IF -d $WAN_BR -j _TRAF_PROT_
#
# Log and drop Class D multicast addresses.
# Illegal as a source address.
#$IPT -A INPUT -i $WAN_IF -s $CLS_D_MLTCST -j _TRAF_PROT_
#
# The next rule denies multicast packets carrying a non-UDP protocol
#$IPT -A INPUT -i $WAN_IF ! -p udp -d $CLS_D_MLTCST -j _TRAF_PROT_
#$IPT -A INPUT -i $WAN_IF   -p udp -d $CLS_D_MLTCST -j ACCEPT
#
# Log and drop Class E reserved IP addresses
#$IPT -A INPUT -i $WAN_IF -s $CLS_E_RESNET -j _TRAF_PROT_
#
# Can't be blocked unilaterally with DHCP.
#$IPT -A INPUT -i $WAN_IF -s $BCST_SRC_NET -j _TRAF_PROT_
#
# Link Local Network..
#$IPT -A INPUT -i $WAN_IF -s $LINK_LCL -j _TRAF_PROT_
#
# TEST-NET.
#$IPT -A INPUT -i $WAN_IF -s $TEST_NET -j _TRAF_PROT_
#
# Silent Drop External Windows Clients Broadcast Traffic.
#$IPT -A INPUT -p UDP -i $WAN_IF -d $WAN_BR --destination-port 135:139 -j _TRAF_PROT_
#
# If we get DHCP requests from the Outside of our network, our logs will
# be swamped as well. This rule will block them from getting logged.
#$IPT -A INPUT -p UDP -i $WAN_IF -d $BCST_DEST --destination-port 67:68 -j _TRAF_PROT_

#
# Drop and Log any packets that interal by default.
# X Window connection establishment
#$IPT -A OUTPUT -o $WAN_IF -p tcp --syn --destination-port $XWINDOW_PORTS -j _TRAF_PROT_
# X Window: incoming connection attempt
#$IPT -A INPUT -i $WAN_IF -p tcp --syn --destination-port $XWINDOW_PORTS -j _TRAF_PROT_
#
#$IPT -A OUTPUT -o $WAN_IF -p tcp -m multiport --destination-port \
#                  $NFS_PORT,$OPENWINDOWS_PORT,$SOCKS_PORT,$SQUID_PORT \
#                  --syn -j _TRAF_PROT_
#
#$IPT -A INPUT -i $WAN_IF -p tcp -m multiport --destination-port \
#                  $NFS_PORT,$OPENWINDOWS_PORT,$SOCKS_PORT,$SQUID_PORT \
#                  --syn -j _TRAF_PROT_

########################################################################
# INPUT chain,  Drop Brutforsers.
#
#$IPT -A INPUT -p tcp -i $WAN_IF -m multiport 
#                   --dports $SSH_LCLP,$SSH_DMZP,$SSH_INTP,$SSH_STDP \
#                   -m recent --set --name SEC --syn -m state --state NEW -j _WAN_SSH_
#
#$IPT -A _WAN_SSH_ -p tcp -m multiport --dports $SSH_LCLP,$SSH_DMZP,$SSH_INTP,$SSH_STDP \
#                  -m recent --update --seconds 60 --hitcount 2 \
#                  --rttl --name SEC -j LOG --log-prefix "BRUTE FORCE "
#
#$IPT -A _WAN_SSH_ -p tcp -m multiport --dports $SSH_LCLP,$SSH_DMZP,$SSH_INTP,$SSH_STDP \
#                  -m recent --update --seconds 60 --hitcount 2 --rttl --name SEC -j _TRAF_PROT_

########################################################################
# FORWARD chain
# Drop bad packets
#
# Drop bad packets in FORWARD chain. Stealth Scans and TCP State Flags.
# Christmas tree packets
#$IPT -A FORWARD -p tcp -m tcp --tcp-flags ALL FIN,PSH,URG -j _TRAF_PROT_
#
# Invalid TCP packets
# New incoming TCP connection packets without SYN flag set
#$IPT -A FORWARD -p tcp ! --syn -m state --state NEW -j _TRAF_PROT_
#
# New state packet with SYN,ACK set
#$IPT -A FORWARD -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j _TRAF_PROT_
#
# TCP packets with SYN,FIN flag set. SYN and FIN are both set.
#$IPT -A FORWARD -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j _TRAF_PROT_
#
# SYN and RST are both set.
#$IPT -A FORWARD -p tcp --tcp-flags SYN,RST SYN,RST -j _TRAF_PROT_
#
# FIN and RST are both set.
#$IPT -A FORWARD -p tcp --tcp-flags FIN,RST FIN,RST -j _TRAF_PROT_
#
# FIN is the only bit set, without the expected accompanying ACK.
#$IPT -A FORWARD -p tcp --tcp-flags ACK,FIN FIN -j _TRAF_PROT_
#
# PSH is the only bit set, without the expected accompanying ACK.
#$IPT -A FORWARD -p tcp --tcp-flags ACK,PSH PSH -j _TRAF_PROT_
#
# URG is the only bit set, without the expected accompanying ACK.
#$IPT -A FORWARD -p tcp --tcp-flags ACK,URG URG -j _TRAF_PROT_
#
# Null packets. All of the bits are cleared.
#$IPT -A FORWARD -p tcp -m tcp --tcp-flags ALL NONE -j _TRAF_PROT_
#
# Drop spoofing packets coming on the WAN interface
#$IPT -A FORWARD -i $WAN_IF -s $LPB_SN -j _TRAF_PROT_
#$IPT -A FORWARD -i $WAN_IF -s $CLS_A -j _TRAF_PROT_
#$IPT -A FORWARD -i $WAN_IF -s $CLS_B -j _TRAF_PROT_
#$IPT -A FORWARD -i $WAN_IF -s $CLS_C -j _TRAF_PROT_
#$IPT -A FORWARD -i $WAN_IF -s $CLS_D_MLTCST -j _TRAF_PROT_
#$IPT -A FORWARD -i $WAN_IF -s $CLS_E_RESNET -j _TRAF_PROT_
#$IPT -A FORWARD -i $WAN_IF -s $BCST_SRC_NET -j _TRAF_PROT_
#$IPT -A FORWARD -i $WAN_IF -s $LINK_LCL -j _TRAF_PROT_
#$IPT -A FORWARD -i $WAN_IF -s $TEST_NET -j _TRAF_PROT_
#$IPT -A FORWARD -i $WAN_IF -s $WAN_IP -j _TRAF_PROT_
#
#$IPT -A _TRAF_PROT_ -j _LOG_DROP_

########################################################################
# WAN Input Chain
#
#$IPT -A INPUT -p tcp -s 192.168.192.100 -i enp0s9 -d 192.168.92.105/24 -j _WAN_IN_
#$IPT -A INPUT -p tcp -i enp0s9 -j _WAN_IN_
#$IPT -A INPUT -p udp -s 192.168.192.100 -i enp0s9 -d 192.168.92.105/24 -j _WAN_IN_
#$IPT -A INPUT -p udp -i enp0s9 -j _WAN_IN_
#
#$IPT -A _WAN_IN_ -m conntrack --ctstate NEW -j LOG --log-prefix="IPT-New: _WAN_IN_ "
#
#$IPT -A _WAN_IN_ -p tcp -i enp0s9  --sport 1025:65535 \
#                 -o enp0s8 --match multiport --dports 2221,25,465,995,993,443,80 \
#                 -m conntrack --ctstate NEW,ESTABLISHED \
#                 -j ACCEPT
#
#$IPT -A _WAN_IN_ -p tcp -i enp0s9  --sport 1025:65535 \
#                 -o enp0s10 --dport 2222 \
#                 -m conntrack --ctstate NEW,ESTABLISHED \
#                 -j ACCEPT
#
#$IPT -A _WAN_IN_ -p tcp -i enp0s8  --dport 1025:65535 \
#                 -o enp0s9 \
#                 --match multiport --sports 2221,25,465,995,993,443,80 \
#                 -m conntrack --ctstate ESTABLISHED \
#                 -j ACCEPT
#
#$IPT -A _WAN_IN_ -p tcp -i enp0s10 --sport 2222 \
#                 -o enp0s9 --dport 1025:65535 \
#                 -m conntrack --ctstate ESTABLISHED \
#                 -j ACCEPT
#
#$IPT -A _WAN_IN_ -p tcp -s 192.168.192.100/24 --sport 1025:65535 \
#                 --match multiport --dports 22,2221:2225,8020:8100,5900:5940,3389 \
#                 -m conntrack --ctstate NEW,ESTABLISHED \
#                 -i enp0s9 -j ACCEPT

# TRACEROTE INPUT from SUPPORT.
#$IPT -A INPUT  -p udp --dport 33434:33524 \
#               -s $SSH_CLI1 -i $WAN_IF -d $WAN_IP \
#               -m conntrack --ctstate NEW -j ACCEPT
#
#$IPT -A _WAN_IN_ -p tcp -i enp0s8 -s 192.168.120.0/24 \
#                 --match multiport --sports 22,2221:2225,8020:8100,5900:5940,3389 \
#                 -o enp0s9 --match multiport --dports 1025:65535 \
#                 -m conntrack --ctstate ESTABLISHED -j ACCEPT

#
# WAN_to_LOGGING and DROP
$IPT -A _WAN_IN_ -j _LOG_DROP_

########################################################################
# _DMZ_OUT_ Chain
########################################################################
#$IPT -A INPUT -p tcp -i enp0s8 -s 192.168.120.0/24 -j _DMZ_OUT_
#$IPT -A INPUT -p udp -i enp0s8 -s 192.168.120.0/24 -j _DMZ_OUT_
#$IPT -A FORWARD -p tcp -i enp0s8 -o enp0s9 -s 192.168.120.0/24 -j _DMZ_OUT_
#$IPT -A FORWARD -p udp -i enp0s8 -o enp0s9 -s 192.168.120.0/24 -j _DMZ_OUT_
#$IPT -A FORWARD -p tcp -i enp0s8 -o enp0s10 -s 192.168.120.0/24 -d 192.168.110.11/24 -j _DMZ_OUT_
#$IPT -A FORWARD -p udp -i enp0s8 -o enp0s10 -s 192.168.120.0/24 -d 192.168.110.11/24 -j _DMZ_OUT_
# DMZ_ to _WAN_
#$IPT -A _DMZ_OUT_ -p tcp -i enp0s8 -o enp0s9 \
#                  -m iprange --src-range 192.168.120.20-192.168.120.25 --sport 1025:65535 \
#                  --match multiport --dports 22,25,465,995,993,443,80 \
#                  -m conntrack --ctstate NEW,ESTABLISHED \
#                  -j ACCEPT
#
#$IPT -A _DMZ_OUT_ -p tcp -i enp0s9 --dport 1025:65535 \
#                  -m iprange --dst-range 192.168.120.20-192.168.120.25 \
#                  --match multiport --sports 22,25,465,995,993,443,80 \
#                  -m conntrack --ctstate ESTABLISHED,RELATED \
#                  -j ACCEPT
#
#$IPT -A _DMZ_OUT_ -p tcp -i enp0s8 --sport 2221 \
#                  -m iprange --dst-range 192.168.120.20-192.168.120.25 \
#                  --match multiport --dports 1025:65535 \
#                  -m conntrack --ctstate ESTABLISHED,RELATED \
#                  -j ACCEPT
#
#$IPT -A _DMZ_OUT_ -p udp -i enp0s8 -o enp0s9 --sport 1025:65535 \
#                  -m iprange --src-range 192.168.120.20-192.168.120.25 \
#                  --match multiport --dports 53,123 \
#                  -m conntrack --ctstate NEW,ESTABLISHED \
#                  -j ACCEPT
#
#$IPT -A _DMZ_OUT_ -p udp -i enp0s9 \
#                  --match multiport --sports 53,123 \
#                  -m iprange --dst-range 192.168.120.20-192.168.120.25 \
#                  --match multiport --dports 1025:65535 \
#                  -m conntrack --ctstate ESTABLISHED,RELATED \
#                  -j ACCEPT
# DMZ_ to _INT_LAN_
#$IPT -A _DMZ_OUT_ -p udp -i enp0s8 -o enp0s10 --sport 1025:65535 \
#                  -m iprange --src-range 192.168.120.20-192.168.120.25 \
#                  -m iprange --dst-range 192.168.110.11-192.168.110.12 \
#                  --dport 53 \
#                  -m conntrack --ctstate NEW,ESTABLISHED \
#                  -j ACCEPT
#
#$IPT -A _DMZ_OUT_ -p tcp -i enp0s8 --sport 53 \
#                  -m iprange --src-range 192.168.120.20-192.168.120.25 \
#                  -m iprange --dst-range 192.168.110.11-192.168.110.12 \
#                  --dport 1025:65535 \
#                  -m conntrack --ctstate ESTABLISHED,RELATED \
#                  -j ACCEPT
#
#$IPT -A _DMZ_OUT_ -p udp -i enp0s8 -o enp0s10 --sport 1025:65535 \
#                  -m iprange --src-range 192.168.120.20-192.168.120.25 \
#                  -m iprange --dst-range 192.168.110.11-192.168.110.12 \
#                  --match multiport --dports 53,123 \
#                  -m conntrack --ctstate NEW,ESTABLISHED \
#                  -j ACCEPT
#
#$IPT -A _DMZ_OUT_ -p udp -i enp0s10 \
#                  --match multiport --sports 53,123 \
#                  -m iprange --src-range 192.168.120.11-192.168.120.25 \
#                  -m iprange --dst-range 192.168.110.11-192.168.110.12 \
#                  --match multiport --dports  1025:65535 \
#                  -m conntrack --ctstate ESTABLISHED,RELATED \
#                  -j ACCEPT
# DMZ_to_LOG and DROP
#$IPT -A _DMZ_OUT_ -j _LOG_DROP_

########################################################################
# Define custom chain LOGGING for diagnostic and control.
# Packets with higher then limit will be rejected
# when not redirected to other chains.
#
#$IPT -N LOGGING
#$IPT -A INPUT   -j LOGGING
#$IPT -A OUTPUT  -j LOGGING
#$IPT -A FORWARD -j LOGGING
#$IPT -A LOGGING -m limit --limit 1800/min -j LOG --log-prefix "IPT-LogPass: " --log-level 4
#$IPT -A LOGGING -j REJECT
#

########################################################################
# INPUT chain close rules.
#
#$IPT -A INPUT -j LOG_DROP
#
#OUTPUT chain close rules.
#$IPT -A OUTPUT -j LOG_DROP
#
# FORWARD chain close rules.
#$IPT -A FORWARD -j LOG_DROP
#

# TEMPLATE for quick RULES.
#$IPT -A INPUT -i $DMZ_IF -p tcp -s $DMZ_SN \
#              --sport $DYNC_PRTS --dport $RGST_PRTS \
#              -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
#$IPT -A OUTPUT -o $DMZ_IF -d $DMZ_SN \
#             --dport $DYNC_PRTS --sport $DYNC_PRTS \
#             -m state --state ESTABLISHED,RELATED -j ACCEPT
