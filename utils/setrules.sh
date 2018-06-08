#!/bin/sh

#
# Usage
#
# setrules <listening interface> <listening interface ip> <wan interface> <wai_port>
#

iptables -t mangle -N wlan0_Trusted && {
iptables -t mangle -N wlan0_Outgoing
iptables -t mangle -N wlan0_Incoming
iptables -t mangle -I PREROUTING 1 -i $1 -j wlan0_Outgoing
iptables -t mangle -I PREROUTING 1 -i $1 -j wlan0_Trusted
iptables -t mangle -I POSTROUTING 1 -o $1 -j wlan0_Incoming
iptables -t nat -N wlan0_Outgoing
iptables -t nat -N wlan0_Router
iptables -t nat -N wlan0_Internet
iptables -t nat -N wlan0_Global
iptables -t nat -N wlan0_Unknown
iptables -t nat -N wlan0_AuthServers
iptables -t nat -A PREROUTING -i $1 -j wlan0_Outgoing
iptables -t nat -A wlan0_Outgoing -d $2 -j wlan0_Router
iptables -t nat -A wlan0_Router -j ACCEPT
iptables -t nat -A wlan0_Outgoing -j wlan0_Internet
iptables -t nat -A wlan0_Internet -m mark --mark 0x2 -j ACCEPT
iptables -t nat -A wlan0_Internet -j wlan0_Unknown
iptables -t nat -A wlan0_Unknown -j wlan0_AuthServers
iptables -t nat -A wlan0_Unknown -j wlan0_Global
iptables -t nat -A wlan0_Unknown -p tcp --dport 80 -j DNAT --to-destination $2:$(expr $4 - 1)
iptables -t nat -A wlan0_Unknown -p tcp --dport 443 -j DNAT --to-destination $2:$4
iptables -t filter -N wlan0_Internet
iptables -t filter -N wlan0_AuthServers
iptables -t filter -N wlan0_Global
iptables -t filter -N wlan0_Known
iptables -t filter -N wlan0_Unknown
iptables -t filter -N wlan0_Traffic_In
iptables -t filter -N wlan0_Traffic_Out
iptables -t filter -I FORWARD -i $1 -j wlan0_Internet
iptables -t filter -A wlan0_Internet -m state --state INVALID -j DROP
iptables -t filter -A wlan0_Internet -o $3 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t filter -A wlan0_Internet -j wlan0_AuthServers
iptables -t filter -A wlan0_AuthServers -d $2 -j ACCEPT
iptables -t filter -A wlan0_Internet -j wlan0_Global
iptables -t filter -A wlan0_Internet -m mark --mark 0x2 -j wlan0_Known
iptables -t filter -A wlan0_Known -d 0.0.0.0/0 -j ACCEPT
iptables -t filter -A wlan0_Internet -j wlan0_Unknown
iptables -t filter -A wlan0_Unknown -d 0.0.0.0/0 -p udp --dport 53 -j ACCEPT
iptables -t filter -A wlan0_Unknown -d 0.0.0.0/0 -p tcp --dport 53 -j ACCEPT
iptables -t filter -A wlan0_Unknown -d 0.0.0.0/0 -p udp --dport 67 -j ACCEPT
iptables -t filter -A wlan0_Unknown -d 0.0.0.0/0 -p tcp --dport 67 -j ACCEPT
iptables -t filter -A wlan0_Unknown -j REJECT --reject-with icmp-port-unreachable
iptables -t filter -I INPUT 1 -j wlan0_Traffic_In
iptables -t filter -I FORWARD 1 -j wlan0_Traffic_Out
}
