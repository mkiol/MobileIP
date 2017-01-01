# Mobile IP implementation for Linux

Partial implementation of [RFC 5944](https://tools.ietf.org/html/rfc5944) Mobile IP framework for Linux, written in Python 2.7.

## Overview

Mobile IP (MIP) framework allows transparent routing of IP packets to mobile nodes regardless of its current point of attachment in a the Internet. Thanks to MIP, mobile node is able to roam from an its home network to any foreign network, being always reachable through its home IP address.

This is only partial implementation of [RFC 5944](https://tools.ietf.org/html/rfc5944) specification.

Following key features are supported:
* Mobile IP protocol (Registration Request and Reply),
* Mobile-Home Authentication Extension (MHAE) with  the 128-bit key HMAC-MD5 authentication algorithm,
* Home Agent entity,
* Mobile Node agent entity,
* Co-loacated care-of address mode
* Forward and Reverse tunneling
* GRE encapsulation
* Indentification based on timestamp

Following key features are not supported:
* Agent discovery and advertisement with ICMP
* Foreign Agent entity
* Minimal encapsulation
* Broadcast datagrams

Basic use case that can be achieved with this implementation of MIP is shown on figure below.

![Basic use case](https://raw.githubusercontent.com/mkiol/MobileIP/master/doc/drawning.png)

## Dependencies
Implementation relays on external components and has the following dependencies:
* iproute2
* pyroute2 Python module
* ntplib Python module
* netaddr Python module

## Usage
MIP implementation is in the single `mip.py` module. See [API documentation](https://github.com/mkiol/MobileIP/blob/master/doc/mip.html) and the examples below to learn how to create and start HA and MN agent.

### Home agent
Example below starts HA service on 10.1.1.20 address and 434 UDP port. HA will accept Registration Requests with authorization SPI=256 (0x100) and KEY="1234567812345678".

```python
import mip

ha = mip.HomeAgent(
      address="10.1.1.20",
      port=434,
      auth_table={256: "1234567812345678"}
      )
ha.start()

# App loop
while True:
    pass
```

### Mobile Node agent
Example below starts MN agent with 10.1.1.10 as a home address. MN will make use of eth0 (default gateway is 10.1.2.5) and wlan0 (default gateway is 10.1.3.5) network interfaces. MN will register its home address using eth0 interface with lifetime 1000 seconds.

```python
import mip
import logging

def exception_handler(e):
    logging.error("Error: %s", e)

mn_agent = mip.MobileNodeAgent(
            mhae_spi=256,
            mhae_key="1234567812345678",
            home_agent="10.1.1.20",
            home_address="10.1.1.10",
            interfaces={"eth0": "10.1.2.5", "wlan0": "10.1.3.5"}
            )

mn_agent.register(ifname="eth0", lifetime=1000,
                  exception_handler=exception_handler)

# App loop
while True:
    pass
```
