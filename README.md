# Wihan [![Build Status](https://api.travis-ci.org/Geenkle/wihan.svg?branch=master)](https://api.travis-ci.org/Geenkle/wihan)

Wihan is a daemon to provide WiFi access and control and hotspot capabilities. It is designed specifically for embedded devices (like routers running OpenWrt).

# Getting Started

#### Prerequisites

You need to have the following dependencies on your target system:

- iptables (http://www.netfilter.org/)
- freeradius-utils (https://freeradius.org/releases/)
- iproute2 (https://github.com/shemminger/iproute2)

>These are common software, so you can easily find the packages for your distribution/system.

>If your system does not provide these packages, you can compile them from scratch.

#### Clone the project

For first you have to clone the project from the github repository:

```git
git clone https://github.com/Geenkle/wihan.git
```

> You can also download the latest release from github (https://github.com/Geenkle/wihan/releases).

#### Compile And Deploy

Enter the project directory and execute:

```
./bootstrap
```

Run the configure script to create the Makefile:

```
./configure --prefix=/usr
```

If you want to cross-compile for another architecture please refer to the cross-compilation instructions
for the autotools. I give you an example of cross-compiling for example for the arm architecture
(yes, I have the toolchain already installed):

```
./configure --prefix=/usr --host=arm-linux
```

Run the make and the make install scripts:
```
make && make install DESTDIR=<some dir>
```

The result is placed in ```<some dir>``` You have to install the content of ```<some dir>``` to your target system.

#### Configure

You can find a sample configuration file in example. Edit the configuration file according to your needs and copy it to /etc/wihan.

>In order to redirect your clients to your captive portal you have to setup the hotspot.cgi script. To setup
>your hotspot.cgi script read it and make your changes as described inside the cgi script.

#### Usage

Start wihan with:

```
wihand -c /etc/wihan/conf
```

It goes in background listening for new connections to the listening interface.

As an host connects to the network owned by the listening interface (e.g. your WiFi network) Wihan will issue a new request
to your radius server and will allow or deny the host from accessing your Internet.

> Wihan does more! It handles the accounting process for all connected hosts sessions as well as bandwidth, session and traffic limits,
> and so on.

The following command return the host status with all related informations in a tabular fashion:

```
wihand -s
```

## License

This project is licensed under the terms of the GNU Lesser General Public License version 2.1.
