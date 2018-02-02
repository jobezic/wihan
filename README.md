# Wihan

Wihan is a daemon to provide WiFi access and control and hotspot capabilities. It is designed specifically for embedded devices (like routers running OpenWrt).
Actually this project is a sort of a framework that should be customized in order to work. The wihand daemon is the mean part of this framework and it is fully functional. Some other minor parts need to be customized.

This project is composed by:

* wihand that is the daemon that handle clients authorization and accounting through radius,
* wihan_redirect that is a little web server based on Mongoose (https://github.com/cesanta/mongoose) that works in collaboration with the hotspot.cgi script to redirect your clients to the captive portal.

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

### Radiusclient

Compile, install and configure Radiusclient on your host (https://wiki.freeradius.org/project/Radiusclient). This is required for wihan to work. It uses the radiusclient and the radacct commands for dealing with your radius server.

## Deployment

copy wihand and wihan_redirect to your bin path.
copy setrules.sh to /etc/wihan

## Configuration

You can find a sample configuration file in example.
Edit the configuration file according to your needs and copy it to /etc/wihan.

### Wihan

Copy the wihan_redirect executable and the hotspot.cgi script on your host.
Copy the wihand executable on your host (e.g. under /usr/bin).

## Usage

In order to redirect your clients to your captive portal you have to setup the hotspot.cgi script and start wihan_redirect.
To setup your hotspot.cgi script read it and make your changes as described inside the cgi script.

Start wihan_redirect with:

```
wihan_redirect
```

Start wihan with:

```wihand -c <config>```

e.g.

```
wihand -c /etc/wihan/config
```

It goes in background listening for new connections to the listening interface.

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

Some steps to go forward:
- wihan_redirect boot script,
- import all radius code inside the wihand daemon (to get rid of the radiusclient dependency),
- some automatization, testing (Travis) and deployment,
- a docker example and image,
- any contributes.

## License

This project is licensed under the terms of the GNU Lesser General Public License version 2.1.
