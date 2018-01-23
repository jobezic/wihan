# Wihan

Wihan is a daemon to provide WiFi access and control and hotspot capabilities. It is designed specifically for embedded devices (like routers running OpenWrt).

## Getting Started

Clone the project on your system:
```
git clone https://github.com/Geenkle/wihan.git
```
### Prerequisites

It needs the following dependencies:
* Radiusclient (https://wiki.freeradius.org/project/Radiusclient)
* iptables (http://www.netfilter.org/)

### Installing

Enter the project directory and execute:

```make```

## Deployment

### Iptables rules

Wihan relies on iptables to redirect the clients traffic. You have to set manually some chains and rules on the host, where <listening interface> is the network interface for the hotspot clients, <listening interface ip> is its own ip and <wan interface> is the wan interface. You can specify an allowed host or domain in <allowed host / domain> for your captive portal. If you want to specify more allowed host or domains you can duplicate the specified rule.
```
iptables -t mangle -N wlan0_Trusted
iptables -t mangle -N wlan0_Outgoing
iptables -t mangle -N wlan0_Incoming
iptables -t mangle -I PREROUTING 1 -i <listening interface> -j wlan0_Outgoing
iptables -t mangle -I PREROUTING 1 -i <listening interface> -j wlan0_Trusted
iptables -t mangle -I POSTROUTING 1 -o <listening interface> -j wlan0_Incoming
iptables -t nat -N wlan0_Outgoing
iptables -t nat -N wlan0_Router
iptables -t nat -N wlan0_Internet
iptables -t nat -N wlan0_Global
iptables -t nat -N wlan0_Unknown
iptables -t nat -N wlan0_AuthServers
iptables -t nat -A PREROUTING -i <listening interface> -j wlan0_Outgoing
iptables -t nat -A wlan0_Outgoing -d <listening interface ip> -j wlan0_Router
iptables -t nat -A wlan0_Router -j ACCEPT
iptables -t nat -A wlan0_Outgoing -j wlan0_Internet
iptables -t nat -A wlan0_Internet -m mark --mark 0x2 -j ACCEPT
iptables -t nat -A wlan0_Internet -j wlan0_Unknown
iptables -t nat -A wlan0_Unknown -j wlan0_AuthServers
iptables -t nat -A wlan0_Unknown -j wlan0_Global
iptables -t nat -A wlan0_Unknown -p tcp --dport 80 -j DNAT --to-destination <listening interface ip>:80
iptables -t nat -A wlan0_Global -d <allowed host/domain> -j ACCEPT
iptables -t filter -N wlan0_Internet
iptables -t filter -N wlan0_AuthServers
iptables -t filter -N wlan0_Global
iptables -t filter -N wlan0_Known
iptables -t filter -N wlan0_Unknown
iptables -t filter -N wlan0_Traffic_In
iptables -t filter -N wlan0_Traffic_Out
iptables -t filter -I FORWARD -i <listening interface> -j wlan0_Internet
iptables -t filter -A wlan0_Internet -m state --state INVALID -j DROP
iptables -t filter -A wlan0_Internet -o <wan interface> -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
iptables -t filter -A wlan0_Internet -j wlan0_AuthServers
iptables -t filter -A wlan0_AuthServers -d <listening interface ip> -j ACCEPT
iptables -t filter -A wlan0_Internet -j wlan0_Global
iptables -t filter -A wlan0_Global -d <allowed host/domain> -j ACCEPT
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
```

## Usage

Start wihan with:

```wihand -l <logfile> -i <listening interface>```

e.g.

```
wihand -l /tmp/wihand.log -i 



```

It goes in background listening for new connections to the br0 interface.

The following command return the host status with all related informations in a tabular fashion:
```
wihand -s
```

If you want to add a mac address of a host to the allowed hosts, just type:
```
/bin/wihand -a <mac>
```
and the hosts will be allowed to pass without any redirection to the captive portal.

## Contributing

Contributors are welcome! Join this nice project!

## License

This project is licensed under the terms of the GNU Lesser General Public License version 2.1.
