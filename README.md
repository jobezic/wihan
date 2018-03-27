# Wihan [![Build Status](https://api.travis-ci.org/Geenkle/wihan.svg?branch=master)](https://api.travis-ci.org/Geenkle/wihan)

Wihan is a daemon to provide WiFi access and control and hotspot capabilities. It is designed specifically for embedded devices (like routers running OpenWrt).

This project is composed by:

* wihand that is the daemon that handle clients authorization and accounting through radius,
* wihan_redirect that is a little web server based on Mongoose (https://github.com/cesanta/mongoose) that works in collaboration with the hotspot.cgi script to redirect your clients to the captive portal.

## Getting Started

Clone the project on your system:
```
git clone https://github.com/Geenkle/wihan.git
```

Enter the project dir and clone the freeradius-client dependency:
```
cd wihan && git clone https://github.com/FreeRADIUS/freeradius-client.git
```

### Prerequisites

It needs iptables (http://www.netfilter.org/) to work, but don't worry because it is installed in all common Linux distributions.

For bandwidth throttling it requires the tc command (https://github.com/shemminger/iproute2) but also this is installed by default in all common Linux distributions.

### Installing

Enter the project directory and execute:

```autoreconf -i```

Run the configure script to create the Makefile and so on:

```./configure --prefix=/usr```

If you want to cross-compile for another architecture please refer to the cross-compilation instructions for the autotools.
I give you an example of cross-compiling for example for the arm architecture (yes, I have the toolchain already installed):

```./configure --prefix=/usr --host=arm-linux```

Run the make and the make install scripts:

```make```

```make install DESTDIR=<somedir>```

The result is a bunch of files in <somedir>. You have to move them to the host architecture (as described below).

## Deployment

Manually copy the content of ```<somedir>``` to the host.

### Configuration

You can find a sample configuration file in example.
Edit the configuration file according to your needs and copy it to /etc/wihan.

In order to redirect your clients to your captive portal you have to setup the hotspot.cgi script and start wihan_redirect.
To setup your hotspot.cgi script read it and make your changes as described inside the cgi script.

## Usage

Start wihan_redirect with:

```
wihan_redirect
```

If you want to put it in background run

```
wihan_redirect &
```

instead.

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
- bandwidth throttling,
- sessions timeout,
- some automatization, testing (Travis) and deployment,
- a docker example and image,
- any contributes.

## License

This project is licensed under the terms of the GNU Lesser General Public License version 2.1.
