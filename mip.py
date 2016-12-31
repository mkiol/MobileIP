# The MIT License (MIT)
#
# Copyright (C) 2016 Michal Kosciesza <michal@mkiol.net>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""Mobile IP implementation.

RFC 5944 implementation of the Mobile IP protocol, Home Agent and
Mobile Node Agent for Linux.
"""

import struct
import socket
import time
import hmac
import logging
import threading
import os
import sys

from ntplib import _to_int as timestamp_to_int
from ntplib import _to_frac as timestamp_to_frac
from ntplib import _to_time as timestamp_to_time
from ntplib import system_to_ntp_time, ntp_to_system_time
from pyroute2 import IPRoute, IPRouteRequest
from netaddr import IPAddress, IPNetwork


INFINITE_LIFETIME = 65535

_ipr = IPRoute()

if not hasattr(socket,'SO_BINDTODEVICE') :
    socket.SO_BINDTODEVICE = 25


def get_ifname(address):
    """Search the interface with given IP address and return
    tuple: interface name and subnet prefix lenght."""

    ifname = None
    prefixlen = None
    addr_list = _ipr.get_addr(address=address)
    if len(addr_list) > 0:
        ifname = addr_list[0].get_attr("IFA_LABEL")
        prefixlen = addr_list[0]["prefixlen"]
    return (ifname, prefixlen)


def get_address(ifname):
    """Search the interface with given name and return
    tuple: interface IP address and subnet prefix lenght."""

    address = None
    prefixlen = None
    addr_list = _ipr.get_addr(label=ifname)
    if len(addr_list) > 0:
        address = addr_list[0].get_attr("IFA_ADDRESS")
        prefixlen = addr_list[0]["prefixlen"]
    return (address, prefixlen)


def get_interfaces_states(interfaces=None):
    """Return dict with state ("UP" or "DOWN") of network interfaces.
    Interface is considered as "UP" if IP address is assigned."""

    states = {}
    links = _ipr.get_links()
    for link in links:
        ifname = link.get_attr("IFLA_IFNAME")
        if interfaces is None or ifname in interfaces:
            ip_list = _ipr.get_addr(family=socket.AF_INET, label=ifname)
            if len(ip_list) > 0:
                state = "UP"
            else:
                state = "DOWN"
            states[ifname] = state
    return states


def _get_default_gw():
    """Return tuple (IP address, interface name, metric) that describes
    default gateway configured in the OS."""

    dr_list = _ipr.get_default_routes(family=socket.AF_INET)
    if len(dr_list) > 0:
        ip = dr_list[0].get_attr("RTA_GATEWAY")
        oif = dr_list[0].get_attr("RTA_OIF")
        met = dr.get_attr("RTA_PRIORITY")
        ifname = _ipr.get_links(oif)[0].get_attr("IFLA_IFNAME")
        return (ip, ifname, met)
    return (None, None, None)


def _get_default_gws():
    """Return list of tuples (IP address, interface name, metric) that
    describes default gateways configured in the OS."""

    result = []
    dr_list = _ipr.get_default_routes(family=socket.AF_INET)
    for dr in dr_list:
        ip = dr.get_attr("RTA_GATEWAY")
        oif = dr.get_attr("RTA_OIF")
        met = dr.get_attr("RTA_PRIORITY")
        ifname = _ipr.get_links(oif)[0].get_attr("IFLA_IFNAME")
        result.append((ip, ifname, met))
    return result


def is_address_in_subnet(address, network):
    """Return True if given IP address belongs to given network."""

    if IPAddress(address) in IPNetwork(network):
        return True
    return False


def is_address_reachable(address):
    """Return True if given IP address belongs to any network configured
    on the OS interfaces."""

    links = _ipr.get_links()
    for link in links:
        ifname = link.get_attr("IFLA_IFNAME")
        list = _ipr.get_addr(family=socket.AF_INET, label=ifname)
        for ipo in list:
            ifaddress = ipo.get_attr("IFA_ADDRESS")
            ifprefixlen = ipo["prefixlen"]
            #logging.debug("address: %s, network: %s/%s", address, ifaddress, ifprefixlen)
            if (ifprefixlen > 0 and
                is_address_in_subnet(address, "%s/%s"%(ifaddress, ifprefixlen))):
                return True
    return False


def _is_route_exists(dst):
    """Return True if destination (IP address/network prefix length,
    e.g. "10.1.0.1/30") belongs to any network configured
    on the OS interfaces."""

    route_list = _ipr.get_routes(family=socket.AF_INET)
    for route in route_list:
        edst = "%s/%d" % (route.get_attr("RTA_DST"), route["dst_len"])
        #logging.debug("edst: %s, dst: %s", edst, dst)
        if dst == edst:
            return True
    return False


def _add_route(dst, gw):
    """Add route entry to the OS route table."""

    if dst == "default" or dst == "0.0.0.0":
        if gw == "default":
            logging.error("Can't add default destination to default gateway.")
            raise Error("Can't add default destination to default gateway.")

    if gw == "default":
        gw = _get_default_gw()[0]
        if gw is None:
            logging.error("Address of default gateway is unknown.")
            raise Error("Address of default gateway is unknown.")

    gw_is_dev = len(_ipr.link_lookup(ifname=gw)) > 0

    if not gw_is_dev:
        if not is_address_reachable(gw):
            logging.warning("Gateway address is not reachable. Not adding.")
            return

    if _is_route_exists(dst):
        logging.warning("Route for dst=%s already exists. " +
                        "Deleting existing route.", dst)
        _ipr.route("del", dst=dst)

    if dst == "default" or dst == "0.0.0.0":
        # Deleting all existing default routes
        _del_all_default_routes()

    # Adding new route
    logging.debug("Adding route: %s -> %s.", dst, gw)
    if gw_is_dev:
        os.system("ip route add %s dev %s" % (dst, gw))
    else:
        _ipr.route("add", dst=dst, gateway=gw)


def _del_all_default_routes():
    """Delete all default route entries from OS route table."""

    gw_list = _get_default_gws()
    for ip, ifname, met in gw_list:
        if ip is None:
            if met is None:
                logging.debug("Deleting default route via %s interface.", ifname)
                os.system("ip route del default dev %s" % ifname)
            else:
                logging.debug("Deleting default route via %s interface with metric %d.", ifname, met)
                os.system("ip route del default dev %s metric %d" % (ifname, met))
        else:
            if met is None:
                logging.debug("Deleting default route to %s via %s interface.", ip, ifname)
                os.system("ip route del default via %s dev %s" % (ip, ifname))
            else:
                logging.debug("Deleting default route to %s via %s interface with metric %d.", ip, ifname, met)
                os.system("ip route del default via %s dev %s metric %d" % (ip, ifname, met))


def _del_route(dst, gw=None):
    """Delete route entry from OS route table."""

    if gw is not None:
        logging.debug("Deleting route: %s -> %s.", dst, gw)
        if len(_ipr.link_lookup(ifname=gw)) > 0:
            os.system("ip route del %s dev %s" % (dst, gw))
        else:
            _ipr.route("del", dst=dst, gateway=gw)
    else:
        logging.debug("Deleting route: %s", dst)
        os.system("ip route del %s" % dst)


def _create_tunnel(name, ip, gre_local, gre_remote, route_dst=None):
    """Create GRE tunnel interface with given name and IP address."""

    logging.debug("Creating %s interface.", name)
    _ipr.link("add", ifname=name, kind="gre",
              gre_local=gre_local,
              gre_remote=gre_remote,
              gre_ttl=255)

    logging.debug("Assigning %s address to %s interface.", ip, name)
    index = _ipr.link_lookup(ifname=name)[0]
    _ipr.link("set", index=index, state="down")
    _ipr.addr("add", index=index, address=ip)
    _ipr.link("set", index=index, state="up")

    if route_dst is not None:
        # Adding new route
        _add_route(route_dst, name)


def _create_interface(name, ip, route_dst=None):
    """Create dummy interface with given name and IP address."""

    logging.debug("Creating %s interface.", name)
    _ipr.link("add", ifname=name, kind="dummy")

    logging.debug("Assigning %s address to %s interface.", ip, name)
    index = _ipr.link_lookup(ifname=name)[0]
    _ipr.link("set", index=index, state="down")
    _ipr.addr("add", index=index, address=ip)
    _ipr.link("set", index=index, state="up")

    if route_dst is not None:
        # Adding new route
        _add_route(route_dst, name)


def _destroy_interface(name):
    """Destroy interface with given name."""

    links = _ipr.link_lookup(ifname=name)
    if len(links) == 0:
        logging.warning("Can't destroy %s interface. It doesn't exist.", name)
        return
    index = links[0]

    # IP addresses assigned to interface
    ip_list = _ipr.get_addr(family=socket.AF_INET, label=name)
    for ipo in ip_list:
        ip = ipo.get_attr("IFA_ADDRESS")

        # Deleting routes
        route_list = _ipr.get_routes(family=socket.AF_INET, gateway=ip)
        for route in route_list:
            rip = route.get_attr("RTA_DST") # route["dst_len"] <- mask
            if rip is not None:
                _del_route("%s/%d" % (rip, route["dst_len"]), ip)
        route_list = _ipr.get_routes(family=socket.AF_INET, scope=253)
        for route in route_list:
            if route.get_attr("RTA_OIF") == index:
                rip = route.get_attr("RTA_DST") # route["dst_len"] <- mask
                if rip is not None:
                    _del_route("%s/%d" % (rip, route["dst_len"]), name)

    # Deleting interface
    logging.debug("Destroying %s interface.", name)
    _ipr.link("set", index=index, state="down")
    _ipr.link("del", index=index)


def _destroy_interfaces(name_prefix):
    """Destroy all interfaces with name starting with given name prefix."""

    for link in _ipr.get_links():
        name = link.get_attr('IFLA_IFNAME')
        if name[0:3] == name_prefix:
            _destroy_interface(name)


def get_ip_forward():
    """Return True if IP-Forward is enabled in the OS."""

    with open("/proc/sys/net/ipv4/ip_forward", "r") as f:
        value = True if int(f.read(1)) == 1 else False
    logging.debug("IP forward is %s.", "enabled" if value else "disabled")
    return value


def set_ip_forward(value):
    """Enable or disable IP-Forward in the OS."""

    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1\n" if value else "0\n")
    logging.debug("IP forward has been %s.", "enabled" if value else "disabled")


def get_proxy_arp(ifname):
    """Return True if Proxy-ARP is enabled in the OS for
    the given interface name."""

    with open("/proc/sys/net/ipv4/conf/%s/proxy_arp" % ifname, "r") as f:
        value = True if int(f.read(1)) == 1 else False
    logging.debug("Proxy ARP for %s interface is %s.", ifname,
                 "enabled" if value else "disabled")
    return value


def set_proxy_arp(ifname, value):
    """Enable or disable Proxy-ARP for given interface name in the OS."""

    with open("/proc/sys/net/ipv4/conf/%s/proxy_arp" % ifname, "w") as f:
        f.write("1\n" if value else "0\n")
    logging.debug("Proxy ARP for %s interface has been %s.", ifname,
                 "enabled" if value else "disabled")


def set_proxy_arp_for_all(value):
    """Enable or disable Proxy-ARP for all interfaces in the OS."""

    link_list = _ipr.get_links()
    for link in link_list:
        if link.get_attr("IFLA_OPERSTATE") == "UP":
            set_proxy_arp(link.get_attr("IFLA_IFNAME"), value)


def ip_to_int(value):
    """Return integer representation of IP address given in dot notation."""

    return struct.unpack("!I", socket.inet_aton(value))[0]


def int_to_ip(value):
    """Convert given IP address in integer representation to dot notation."""

    return socket.inet_ntoa(struct.pack("!I", value))


def str_to_hex(string):
    """Convert given string to hex string."""

    return ":".join("{:02x}".format(ord(c)) for c in string)


class Error(Exception):
    """Unspecified exception raised by MIP module."""
    pass


class RegistrationFailed(Error):
    """Mobile Node Agent registration failed exception."""
    pass


class Extension:
    """Mobile IP Extension class."""

    TYPE_MHAE = 32 # Mobile-Home Authentication Extension
    TYPE_MFAE = 33 # Mobile-Foreign Authentication Extension
    TYPE_FHAE = 34 # Foreign-Home Authentication Extension

    _TYPE_DESC_TABLE = {
        32: "Mobile-Home Authentication Extension",
        33: "Mobile-Foreign Authentication Extension",
        34: "Foreign-Home Authentication Extension"
    }

    def __init__(self, type, length, data=None):
        """MIP Extension constructor.

        Parameters:
        type    -- type of extension (e.g. Extension.TYPE_MHAE)
        length  -- lenght of data (number of bytes) in the extension
        data    -- data in the extension (optional)
        """

        if data is not None and len(data) != length:
            logging.error("Length of data is invalid.")
            raise Error("Length of data is invalid.")
        self.type = type
        self.length = length
        self.data = data

    def __str__(self):
        return "<MobileIP Extension, Type: %d, Length: %d>" % (self.type,
                    self.length)



class MobileHomeAuthExtension(Extension):
    """Mobile IP Mobile-Home Authentication Extension class for 128-bit
    HMAC-MD5."""

    _LENGTH = 20

    def __init__(self, spi, authenticator=None):
        """MHAE constructor.

        Parameters:
        spi           -- SPI value
        authenticator -- Authentication data (optional)
        """

        Extension.__init__(self, Extension.TYPE_MHAE,
                           MobileHomeAuthExtension._LENGTH)
        self.spi = spi
        self.authenticator = authenticator

    def __str__(self):
        return "<MobileIP Mobile-Home Auth Extension, SPI: %d>" % self.spi



class Packet:
    """Mobile IP packet class."""

    TYPE_REG_REQUEST = 1
    TYPE_REG_REPLY = 3

    _TYPE_DESC_TABLE = {
        1: "Registration Request",
        3: "Registration Reply"
    }

    _FORMAT = "!B" # MIP packet format: first byte defines packet Type


    def __init__(self, type, extensions=None):
        """MIP packet constructor.

        Parameters:
        type       -- type of MIP packet (e.g. Packet.TYPE_REG_REQUEST)
        extensions -- list of Extension instances (optional)
        """

        self.type = type
        self.extensions = [] if extensions is None else extensions


    def __str__(self):
        return "<MobileIP packet, Type: %i (%s), Extensions: %s>" % (
            self.type, Packet._TYPE_DESC_TABLE[self.type], self.extensions)


    def to_data(self):
        """Return byte array representation of the packet."""

        logging.error("Unable to get data.")
        raise Error("Unable to get data.")


    def _calculate_mhae(self, spi, key):
        """Create and return MobileHomeAuthExtension of this packet."""

        packed = self.to_data()
        extension = MobileHomeAuthExtension(spi)
        try:
            packed += struct.pack("!2BI", extension.type, extension.length, spi)
        except struct.error:
            logging.error("Invalid MIP Mobile-Home Auth Extension fields.")
            raise Error("Invalid MIP Mobile-Home Auth Extension fields.")
        extension.authenticator = hmac.new(key, packed).digest()
        return extension


    def add_mhae(self, spi, key):
        """Create and add MobileHomeAuthExtension of this packet
        with given SPI and KEY."""

        # Deleting existing MHAE
        for extension in self.extensions[:]:
            if extension.type == Extension.TYPE_MHAE:
                self.extensions.remove(extension)
        self.extensions.append(self._calculate_mhae(spi, key))

    def get_mhae(self):
        """Return MobileHomeAuthExtension of this packet."""

        for extension in self.extensions:
            if extension.type == Extension.TYPE_MHAE:
                return extension

    def verify_mhae(self, spi, key):
        """Return True if MobileHomeAuthExtension in this packet is valid
        for given SPI and KEY."""

        new_extensions = []
        for extension in self.extensions:
            if extension.type == Extension.TYPE_MHAE and extension.spi == spi:
                mhae = extension
                break
            new_extensions.append(extension)
        old_extensions = self.extensions
        self.extensions = new_extensions
        authenticator = self._calculate_mhae(spi, key).authenticator
        self.extensions = old_extensions
        return mhae.authenticator == authenticator

    @staticmethod
    def from_data(data):
        """Create and return MIP packet based on given byte data."""

        try:
            unpacked = struct.unpack(Packet._FORMAT,
                data[0:struct.calcsize(Packet._FORMAT)])
        except struct.error:
            logging.error("Invalid MIP packet.")
            raise Error("Invalid MIP packet.")

        if unpacked[0] == Packet.TYPE_REG_REQUEST:
            return RegRequestPacket.from_data(data)
        if unpacked[0] == Packet.TYPE_REG_REPLY:
            return RegReplyPacket.from_data(data)

        logging.error("Unknown MIP packet type.")
        raise Error("Unknown MIP packet type.")

    @staticmethod
    def _extensions_from_data(data):
        """Create and return list Extension instances based on
        given byte data."""

        extensions = []
        i = 0
        while i < len(data):
            try:
                unpacked = struct.unpack("!2B", data[i:i+2])
            except struct.error:
                logging.error("Invalid MIP Extension data.")
                raise Error("Invalid MIP Extension data.")

            type = unpacked[0]
            length = unpacked[1]

            if type == Extension.TYPE_MHAE:
                try:
                    unpacked = struct.unpack("!I", data[i+2:i+2+4])
                except struct.error:
                    logging.error("Invalid MIP Mobile-Home Auth Extension data.")
                    raise Error("Invalid MIP Mobile-Home Auth Extension data.")
                spi = unpacked[0]
                authenticator = data[i+2+4:i+2+length]
                extensions.append(MobileHomeAuthExtension(spi,
                    authenticator=authenticator))
            else:
                extensions.append(Extension(type, length,
                    data[i+2:i+2+length]))

            i += 2+length

        return extensions

    def _extensions_to_data(self, packed):
        for extension in self.extensions:
            if isinstance(extension, MobileHomeAuthExtension):
                try:
                    packed += struct.pack("!2BI",extension.type,
                        extension.length, extension.spi)
                    packed += extension.authenticator[0:extension.length-4]
                except struct.error:
                    logging.error("Invalid MIP Mobile-Home Auth Extension fields.")
                    raise Error("Invalid MIP Mobile-Home Auth Extension fields.")
            else:
                try:
                    packed += struct.pack("!2B", extension.type,
                        extension.length) + extension.data[0:extension.length]
                except struct.error:
                    logging.error("Invalid MIP Extension fields.")
                    raise Error("Invalid MIP Extension fields.")
        return packed



class RegRequestPacket(Packet):
    """Mobile IP Registration Request packet class."""

    FLAG_S = 0B10000000  # Simultaneous bindings
    FLAG_B = 0B01000000  # Broadcast datagrams
    FLAG_D = 0B00100000  # Decapsulation by mobile node
    FLAG_M = 0B00010000  # Minimal encapsulation
    FLAG_G = 0B00001000  # GRE encapsulation
    FLAG_r = 0B00000100  # reserved
    FLAG_T = 0B00000010  # Reverse Tunneling requested
    FLAG_x = 0B00000001  # reserved

    _FLAG_DESC_TABLE = {
        0B10000000: "S",
        0B01000000: "B",
        0B00100000: "D",
        0B00010000: "M",
        0B00001000: "G",
        0B00000100: "r",
        0B00000010: "T",
        0B00000001: "x"
    }

    _FORMAT = "!2B H 5I"

    def _print_flags_desc(self):
        desc = ""
        for key, value in RegRequestPacket._FLAG_DESC_TABLE.iteritems():
            desc += value if self.flags & key else ""
        return desc

    def __init__(
            self,
            flags,
            lifetime,
            home_address,
            home_agent,
            care_of_address,
            identification = None, # timestamp
            extensions = None
        ):
        """MIP Registration Request constructor.

        Parameters:
        flags           -- flags that will be included in to request
        lifetime        -- Lifetime value
        home_address    -- Home IP address (dot notation)
        home_agent      -- Home Agent IP address (dot notation)
        care_of_address -- Care-of IP address (dot notation)
        identification  -- Identification value
        extensions      -- list of Extension instances
        """
        Packet.__init__(self, Packet.TYPE_REG_REQUEST, extensions)
        self.flags = flags
        self.lifetime = lifetime
        self.home_address = home_address
        self.home_agent = home_agent
        self.care_of_address = care_of_address
        self.identification = (system_to_ntp_time(time.time())
                               if identification is None else identification)
        self.expiration_date = 0 # timestamp when binding will expire

    def __str__(self):
        return ("<MobileIP Reg Request, Flags: %d (%s), Lifetime: %d, " +
        "Home address: %s, Home agent: %s, Care-of address: %s, " +
        "Identification: %f, Extensions: %s>") % (
            self.flags,
            self._print_flags_desc(),
            self.lifetime,
            self.home_address,
            self.home_agent,
            self.care_of_address,
            self.identification,
            self.extensions
        )

    def is_update_request(self, reg_req_packet):
        """Return True if given RegRequestPacket is an update."""

        return (self.home_address == reg_req_packet.home_address and
                self.home_agent == reg_req_packet.home_agent and
                self.care_of_address == reg_req_packet.care_of_address)

    def update_identification(self):
        """Update Identification value in the request."""

        self.identification = system_to_ntp_time(time.time())

    @staticmethod
    def from_data(data):
        """Create and return RegRequestPacket based on given byte data."""

        try:
            unpacked = struct.unpack(
                RegRequestPacket._FORMAT,
                data[0:struct.calcsize(RegRequestPacket._FORMAT)])
        except struct.error:
            logging.error("Invalid MIP Registration Request packet.")
            raise Error("Invalid MIP Registration Request packet.")

        extensions = Packet._extensions_from_data(
            data[struct.calcsize(RegRequestPacket._FORMAT):len(data)])

        return RegRequestPacket(
                unpacked[1],
                unpacked[2],
                int_to_ip(unpacked[3]),
                int_to_ip(unpacked[4]),
                int_to_ip(unpacked[5]),
                timestamp_to_time(unpacked[6], unpacked[7]),
                extensions
        )

    def to_data(self):
        """Return byte array representation."""

        try:
            packed = struct.pack(RegRequestPacket._FORMAT,
                self.type,
                self.flags,
                self.lifetime,
                ip_to_int(self.home_address),
                ip_to_int(self.home_agent),
                ip_to_int(self.care_of_address),
                timestamp_to_int(self.identification),
                timestamp_to_frac(self.identification)
            )
        except struct.error:
            logging.error("Invalid Registration Request packet fields.")
            raise Error("Invalid Registration Request packet fields.")
        return self._extensions_to_data(packed)



class RegReplyPacket(Packet):
    """Mobile IP Registration Reply packet class."""

    CODE_ACCEPTED = 0
    CODE_DENIED_BY_FA = 64
    CODE_DENIED_BY_HA = 128
    CODE_MN_FAILED_AUTH = 131
    CODE_IDENT_MISMATCH = 133

    _CODE_DESC_TABLE = {
        0: "Registration accepted",
        1: "Registration accepted, mobility bindings unsupported",
        64: "Reason unspecified",
        65: "Administratively prohibited",
        66: "Insufficient resources",
        67: "Mobile node failed authentication",
        68: "Home agent failed authentication",
        69: "Requested Lifetime too long",
        70: "Poorly formed Request",
        71: "Poorly formed Reply",
        72: "Requested encapsulation unavailable",
        73: "Reserved and unavailable",
        77: "Invalid care-of address",
        78: "Registration timeout",
        80: "Home network unreachable (ICMP error received)",
        81: "Home agent host unreachable (ICMP error received)",
        82: "Home agent port unreachable (ICMP error received)",
        88: "Home agent unreachable (other ICMP error received)",
        194: "Invalid Home Agent Address",
        128: "Reason unspecified",
        129: "Administratively prohibited",
        130: "Insufficient resources",
        131: "Mobile node failed authentication",
        132: "Foreign agent failed authentication",
        133: "Registration Identification mismatch",
        134: "Poorly formed Request",
        135: "Too many simultaneous mobility bindings",
        136: "Unknown home agent address"
    }

    _FORMAT = "!2B H 4I"

    def __init__(
            self,
            code,
            lifetime,
            home_address,
            home_agent,
            identification,
            extensions = None,
        ):
        """MIP Registration Reply constructor.

        Parameters:
        code            -- code of the reply (e.g. RegReplyPacket.CODE_ACCEPTED)
        lifetime        -- Lifetime value
        home_address    -- Home IP address (dot notation)
        home_agent      -- Home Agent IP address (dot notation)
        identification  -- Identification value
        extensions      -- list of Extension instances
        """

        Packet.__init__(self, Packet.TYPE_REG_REPLY, extensions)
        self.code = code
        self.lifetime = lifetime
        self.home_address = home_address
        self.home_agent = home_agent
        self.identification = identification
        self.expiration_date = 0 # timestamp when binding will expire

    def __str__(self):
        return ("<MobileIP Reg Reply, Code: %d (%s), Lifetime: %d, " +
        "Home address: %s, Home agent: %s, Identification: %f, " +
        "Extensions: %s>") % (
            self.code,
            RegReplyPacket._CODE_DESC_TABLE[self.code],
            self.lifetime,
            self.home_address,
            self.home_agent,
            self.identification,
            self.extensions
        )

    @staticmethod
    def from_data(data):
        """Create and return RegReplyPacket based on given byte data."""

        try:
            unpacked = struct.unpack(
                RegReplyPacket._FORMAT,
                data[0:struct.calcsize(RegReplyPacket._FORMAT)])
        except struct.error:
            logging.error("Invalid MIP Registration Reply packet.")
            raise Error("Invalid MIP Registration Reply packet.")

        extensions = Packet._extensions_from_data(
            data[struct.calcsize(RegReplyPacket._FORMAT):len(data)])

        return RegReplyPacket(
                unpacked[1],
                unpacked[2],
                int_to_ip(unpacked[3]),
                int_to_ip(unpacked[4]),
                timestamp_to_time(unpacked[5], unpacked[6]),
                extensions
        )

    def to_data(self):
        """Return byte array representation."""

        try:
            packed = struct.pack(RegReplyPacket._FORMAT,
                self.type,
                self.code,
                self.lifetime,
                ip_to_int(self.home_address),
                ip_to_int(self.home_agent),
                timestamp_to_int(self.identification),
                timestamp_to_frac(self.identification)
            )
        except struct.error:
            logging.error("Invalid MIP Registration Reply packet fields.")
            raise Error("Invalid MIP Registration Reply packet fields.")
        return self._extensions_to_data(packed)



class _BindingChecker(threading.Thread):
    """Binding checker class."""

    _SLEEP_TIME = 1

    def __init__(self, lock, binding_table, lifetime_expired_handler):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.binding_table = binding_table
        self.lifetime_expired_handler = lifetime_expired_handler
        self.active = False
        self.lock = lock

    def start(self):
        self.active = True
        threading.Thread.start(self)

    def stop(self):
        if self.is_alive():
            self.active = False

    def run(self):
        while self.active:
            keys_to_handle = []
            self.lock.acquire()
            t = time.time()
            for key, packet in self.binding_table.iteritems():
                if 0 <= packet.expiration_date <= t:
                    keys_to_handle.append(key)
            self.lock.release()
            for key in keys_to_handle:
                self.lifetime_expired_handler(packet)
            time.sleep(_BindingChecker._SLEEP_TIME)



class _Timer(threading.Thread):
    """Call a function after a specified number of seconds"""

    def __init__(self, interval, function, exception_handler=None,
                 args=None, kwargs=None):
        threading.Thread.__init__(self)
        self.interval = interval
        self.function = function
        self.exception_handler = exception_handler
        self.args = args if args is not None else []
        self.kwargs = kwargs if kwargs is not None else {}
        self.finished = threading.Event()

    def cancel(self):
        """Stop the timer if it hasn't finished yet."""

        self.finished.set()

    def run(self):
        self.finished.wait(self.interval)

        if not self.finished.is_set():
            try:
                self.function(*self.args, **self.kwargs)
            except Exception,e:
                logging.error("Exception has been thrown in the Timer thread.")
                logging.exception(e)
                if self.exception_handler is not None:
                    self.exception_handler(e)

        self.finished.set()


class MobileNodeAgent:
    """Mobile IP Mobile Node agent"""

    def __init__(self, mhae_spi, mhae_key, home_agent, home_address,
                 interfaces,
                 port=434,
                 flags=(RegRequestPacket.FLAG_D |
                        RegRequestPacket.FLAG_G |
                        RegRequestPacket.FLAG_T),
                 timeout=3,
                 num_of_retr=2,
                 rereg_time=0.8,
                 wait_for_dereg_reply=True,
        ):
        """Mobile Node Agent constructor.

        Parameters:
        mhae_spi             -- SPI value needed for MHAE calculation (decimal integer)
        mhae_key             -- KEY value needed for MHAE calculation (string)
        home_agent           -- Home Agent IP address (dot notation)
        home_address         -- Home IP address (dot notation)
        interfaces           -- dict that conctains interface names as keys
                                and default gateway IP addresses as values,
                                e.g. {"eth0": "10.1.2.5", "wlan0": "10.1.3.5"}
        port                 -- Home Agent service UDP port number (default is 434)
        flags                -- flags included in MIP requests
                                (default is FLAG_D | FLAG_G | FLAG_T)
        timeout              -- maximum waiting time (seconds) for
                                the HA response (default is 3)
        num_of_retr          -- number of request retries (default is 2)
        rereg_time           -- requested time of reregistration,
                                e.g. 0.5 means that reregistraton will be
                                after 0.5*lifetime (default is 0.8)
        wait_for_dereg_reply -- indicator if agent should wait for
                                deregistration reply form HA (default is True)
        """

        # Only co-located care-of address is supported, so
        # D flag (Decapsulation by mobile node) is mandatory.
        # Only GRE tunnel is supported, so G flag is mandatory and M is not allowed.
        # Reverse Tunneling is mandatory, so T flag is mandatory
        if not flags & RegRequestPacket.FLAG_D:
            raise Error("D flag is not set but is mandatory.")
        if not flags & RegRequestPacket.FLAG_G:
            raise Error("G flag is not set but is mandatory.")
        if not flags & RegRequestPacket.FLAG_T:
            raise Error("T flag is not set but is mandatory.")
        if flags & RegRequestPacket.FLAG_M:
            raise Error("M flag is set but is not supported.")

        self.mhae_spi = mhae_spi
        self.mhae_key = mhae_key
        self.home_agent = home_agent
        self.home_address = home_address
        self.port = port
        self.flags = flags
        self.timeout = timeout
        self.num_of_retr = num_of_retr
        self.rereg_time = rereg_time
        self.wait_for_dereg_reply =  wait_for_dereg_reply
        self._listening = False
        self._rereg_timer = None
        self._socket = None
        self._sent_reg_reqest = None
        self._received_reg_reply = None
        self._num_of_retr_done = 0
        self._closing = False
        self._is_rereg = False
        self._exception_handler = None
        self._gateway = None
        self._interfaces = interfaces
        self._lock = threading.Lock()

        # Create dummy interface with home address
        _destroy_interfaces("mip")
        _del_route(home_agent+"/32")
        _create_interface("mip0", home_address)


    def __del__(self):
        """Mobile Node Agent destructor"""

        # Destroying all mipX interfaces
        _destroy_interfaces("mip")
        if self._gateway is not None:
            # Recreating original default routing
            _add_route(dst="default", gw=self._gateway)
            self._gateway = None


    def _update_routes(self, ifname):
        """Create or update static route to Home Agent IP address."""

        gw = self._interfaces[ifname]
        if gw is None:
            logging.error("Unknown gateway address.")
            raise Error("Unknown gateway address.")
        # Creating static route to home agent
        _add_route(self.home_agent+"/32", gw)


    def _create_tunnel(self, reg_req_packet):
        """Create GRE tunnel to Home Agent IP address."""

        #ifname, prefixlen = get_ifname(reg_req_packet.care_of_address)
        #gw = self._interfaces[ifname]
        #if gw is None:
            #gw = _get_default_gw()[0]
            #if gw is None:
        #    raise Error("Unknown gateway address.")
            #self._gateway = gw # Saving default route gateway

        # Creating static route to home agent
        #_add_route(self.home_agent+"/32", gw)

        _create_tunnel(name="mip1",
                       ip=self.home_address,
                       gre_local=reg_req_packet.care_of_address,
                       gre_remote=reg_req_packet.home_agent,
                       route_dst="default")


    def _destroy_tunnel(self):
        """Destroy GRE tunnel to Home Agent IP address."""

        _destroy_interface("mip1")

        #if self._gateway is not None:
        #    # Recreating original default routing
        #    _add_route(dst="default", gw=self._gateway)
        #    self._gateway = None

        # Recreating default routing
        #for ifname in self._interfaces.keys():
        #    if is_address_reachable(self._interfaces[ifname]):
        #        logging.info("Setting default route for %s interface.", ifname)
        #        _add_route(dst="default", gw=self._interfaces[ifname])
        #        break

        # Deleting static route to home agent
        #_del_route(self.home_agent+"/32")


    def _stop_listening_stuff(self):
        # Destroying tunnel
        if self.is_registered():
            self._destroy_tunnel()
            #_del_route(self.home_agent+"/32")

        self._sent_reg_reqest = None
        self._is_rereg = False
        self._stop_listening()


    def _data_handler(self, data, addr):
        """Handle received data."""

        try:
            in_packet = Packet.from_data(data)
        except Error:
            logging.error("Invalid data received.")
            return

        logging.debug("Connected by %s host on %d port.", addr[0], addr[1])
        logging.debug("Received: %s", in_packet)
        #logging.debug("Extensions:")
        #for extension in in_packet.extensions:
        #    logging.info(extension)

        if not isinstance(in_packet, RegReplyPacket):
            logging.error("Invalid packet type has been received. " +
                            "Discarding packet.")
            return

        # Registration Reply received
        logging.info("Registration Reply has been received.")

        # Identification verification
        if in_packet.identification != self._sent_reg_reqest.identification:
            logging.warning("Reply has unknown identification. " +
                            "Discarding packet.")
            return

        # MHAE verification
        mhae = in_packet.get_mhae()
        if mhae is None or mhae.spi != self.mhae_spi:
            # Can't find matching SPI
            logging.warning("Can't find matching MHAE SPI in reply. " +
                            "Discarding packet.")
            return
        if not in_packet.verify_mhae(self.mhae_spi, self.mhae_key):
            # Authorization failed
            logging.warning("Reply authorization is failed.")
            self._stop_listening_stuff()
            self._lock.release()
            raise RegistrationFailed("Reply authorization is failed.")

        # Registration Reply code verification
        if in_packet.code is not RegReplyPacket.CODE_ACCEPTED:
            # Registration is not accepted
            logging.warning("Registration request has not been accepted.")
            self._stop_listening_stuff()
            self._lock.release()
            raise RegistrationFailed("Registration has not been accepted.")

        # Registration Reply lifetime verification
        if in_packet.lifetime <= 0:
            # Registration lifetime is 0
            if self._sent_reg_reqest.lifetime != 0:
                logging.warning("Reply lifetime is 0, but 0 wasn't requested.")
            logging.debug("Reply lifetime is 0, so reply for deregistration.")
            self._stop_listening_stuff()
            return

        # Registration is accepted
        logging.info("Registration request has been accepted.")

        # Verifing reply lifetime
        if in_packet.lifetime > self._sent_reg_reqest.lifetime:
            logging.warning("Lifetime in reply is longer than requested.")
            in_packet.lifetime = self._sent_reg_reqest

        # Saving reply
        self._received_reg_reply = in_packet

        # Setting up reregistration timer
        if self._rereg_timer is not None:
            logging.error("Rereg timer is not empty.")
        self._rereg_timer = _Timer(
            in_packet.lifetime * self.rereg_time, self._reregister,
            exception_handler=self._exception_handler)
        self._rereg_timer.start()

        # Creating tunnel
        if not self._is_rereg:
            #if self._sent_reg_reqest.flags & RegRequestPacket.FLAG_T:
            self._create_tunnel(self._sent_reg_reqest)

        self._stop_listening()
        self._is_rereg = False


    def _send_packet(self, packet, addr):
        """Send given packet to given IP address."""

        logging.debug("Sending: %s", packet)
        self._socket.sendto(packet.to_data(), addr)


    def is_registered(self):
        """Return True if agent is registered."""

        if self._is_rereg:
            return True
        return self._received_reg_reply is not None


    def get_status(self):
        """Return string containing status information."""

        if not self.is_registered():
            return {"registered": False}
        ifname, prefixlen = get_ifname(address=self._sent_reg_reqest.care_of_address)
        if ifname is None:
            logging.error("Care-of address %s is not assigned " +
                          "to any interface.", self._sent_reg_reqest.care_of_address)
        return {
            "registered": True,
            "home_address": self.home_address,
            "home_agent": self.home_agent,
            "care_of_address": self._sent_reg_reqest.care_of_address,
            "ifname": ifname
            }


    def register(self, care_of_address=None, dereg_existing_reg=True,
                 lifetime=INFINITE_LIFETIME, ifname=None,
                 exception_handler=None):
        """Register Mobile Node Agent in Home Agent.

        Parameters:
        care_of_address    -- Care-of address (optional if ifname is provided)
        dereg_existing_reg -- if True, deregistration will be done
                              before new registration (default is True)
        lifetime           -- requested registration lifetime value
        ifname             -- name of network interface for the registration
                              (optional if care_of_address is provided)
        exception_handler  -- function that will be called when exception
                              occures in Mobile Node Agent thread
        """

        self._lock.acquire()

        prefixlen = None

        # Addresses verification
        if care_of_address is None and ifname is None:
            logging.error("At least care-of address or interface " +
                          "name needs to be provided.")
            self._lock.release()
            raise Error("Care-of address or interface name not provided")
        if care_of_address is None:
            care_of_address, prefixlen = get_address(ifname=ifname)
            if care_of_address is None or prefixlen is None:
                logging.error("Interface %s has no address assigned or " +
                              "doesn't exist.", ifname)
                self._lock.release()
                raise RegistrationFailed("Interface has no address assigned.")
        if ifname is None or prefixlen is None:
            ifname, prefixlen = get_ifname(address=care_of_address)
            if ifname is None or prefixlen is None:
                logging.error("Care-of address %s is not assigned " +
                              "to any interface.", care_of_address)
                self._lock.release()
                raise RegistrationFailed("Care-of address is not assigned to any interface.")
        if is_address_in_subnet(self.home_address,
                                "%s/%d"%(care_of_address, prefixlen)):
            logging.error("Home address (%s) belongs to " +
                          "care-of address subnet (%s/%d), so you are in " +
                          "the home network.", self.home_address,
                          care_of_address, prefixlen)
            self._lock.release()
            raise RegistrationFailed("Home address belongs to care-of address subnet.")

        # Check if already registered
        if self.is_registered():
            if (self._sent_reg_reqest.care_of_address == care_of_address and
                self.rereg_time is not None):
                self._exception_handler = exception_handler # updating handler
                logging.warning("Care-of address is already registered. "+
                                "Request will not be sent.")
                self._lock.release()
                return

        # Disabling rereg timer
        if self._rereg_timer is not None:
            self._rereg_timer.cancel()
            self._rereg_timer = None

        # Updating routes for home gateway
        self._update_routes(ifname)

        # Auto deregistration
        if self.is_registered():
            if dereg_existing_reg:
                self.deregister(ifname=ifname)
            else:
                self.cancel()

        # Resets
        #self._destroy_tunnel()
        self._closing = False
        self._received_reg_reply = None
        self._num_of_retr_done = 0
        self._is_rereg = False

        # Creating Registration Request
        out_packet = RegRequestPacket(
            flags=self.flags,
            lifetime=lifetime,
            home_address=self.home_address,
            home_agent=self.home_agent,
            care_of_address=care_of_address
        )
        out_packet.add_mhae(self.mhae_spi, self.mhae_key)

        # Saving reg request
        self._sent_reg_reqest = out_packet
        self._exception_handler = exception_handler

        logging.info("Sending Registration Request to %s (Home Agent) " +
                     "using %s interface.", self.home_agent, ifname)
        #logging.debug("care_of_address: %s, ifname: %s, prefixlen: %s",
        #              care_of_address, ifname, prefixlen)
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind((care_of_address, 0))
        self._socket.setsockopt(socket.SOL_SOCKET,
                                socket.SO_BINDTODEVICE, ifname)
        self._send_packet(out_packet, (self.home_agent, self.port))

        # Listening for reply
        self._start_listening()
        self._lock.release()


    def deregister(self, ifname=None, wait_for_reply=None):
        """Deregister Mobile Node Agent.

        Parameters:
        ifname         -- name of network interface for the deregistration,
                          if not provided ifname will the same as for
                          the registration (optional)
        wait_for_reply -- if True, positive reply from Home Agent is required
                          to accept deregistration (default is
                          wait_for_dereg_reply provided in constructor)
        """

        # Disabling rereg timer
        if self._rereg_timer is not None:
            self._rereg_timer.cancel()
            self._rereg_timer = None

        if not self.is_registered():
            logging.warning("There is nothing to deregister.")
            return

        # Resets
        self._received_reg_reply = None
        self._num_of_retr_done = self.num_of_retr # disable retransmissions
        self._rereg_timer = None
        self._closing = False

        self._is_rereg = True

        # Creating Deregistration Request
        self._sent_reg_reqest.update_identification()
        self._sent_reg_reqest.lifetime = 0 # Deregistration
        self._sent_reg_reqest.add_mhae(self.mhae_spi, self.mhae_key)

        care_of_address = self._sent_reg_reqest.care_of_address
        difname, prefixlen = get_ifname(address=care_of_address)

        if ifname is None and difname is None:
            logging.error("Care-of address %s is not assigned " +
                          "to any interface. Cancelling registration.",
                          care_of_address)
            self.cancel()
            self._lock.release()
            return

        if ifname is None or difname == ifname:
            logging.debug("Care-of address %s is assigned " +
                         "to interface.", care_of_address)
        else:
            address, prefixlen = get_address(ifname=ifname)
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.bind((address, 0))
            self._socket.setsockopt(socket.SOL_SOCKET,
                                    socket.SO_BINDTODEVICE, ifname)

        logging.info("Sending Deregistration Request to %s (Home Agent) " +
                     "via %s interface.",
                     self._sent_reg_reqest.home_agent, ifname)

        self._send_packet(self._sent_reg_reqest,
                          (self._sent_reg_reqest.home_agent, self.port))

        if (self.wait_for_dereg_reply if wait_for_reply is None
            else wait_for_reply):
            # Waiting for reply
            #logging.info("Waiting for deregistration reply.")
            self._start_listening()
        else:
            self._is_rereg = False
            # Not waiting for reply, so destroying reverse tunnel immediately
            #if self._sent_reg_reqest.flags & RegRequestPacket.FLAG_T:
            self._destroy_tunnel()


    def _handle_listening_timeout(self):
        logging.warning("Request has timeout.")
        if self.num_of_retr > self._num_of_retr_done and not self._closing:
            # Doing retransmission
            self._num_of_retr_done += 1 # increasing counter
            logging.warning("Repeating request, #%d attempt.",
                         self._num_of_retr_done)
            #self._sent_reg_reqest.update_identification()
            self._sent_reg_reqest.add_mhae(self.mhae_spi, self.mhae_key)

            self._send_packet(self._sent_reg_reqest,
                              (self.home_agent, self.port))
        else:
            # Reg request is failed
            logging.error("Registration Request is failed due to timeout.")
            self.cancel()
            return


    def _reregister(self):
        self._lock.acquire()

        logging.info("Refreshing registration.")

        care_of_address = self._sent_reg_reqest.care_of_address
        ifname, prefixlen = get_ifname(address=care_of_address)

        if ifname is None or prefixlen is None:
            logging.error("Care-of address %s is not assigned " +
                          "to any interface. Cancelling registration.",
                          care_of_address)
            self.cancel()
            self._lock.release()
            return

        # Resets
        self._received_reg_reply = None
        self._num_of_retr_done = 0
        self._rereg_timer = None
        self._is_rereg = True

        # Updating Registration Request
        self._sent_reg_reqest.update_identification()
        self._sent_reg_reqest.add_mhae(self.mhae_spi, self.mhae_key)

        logging.info("Sending Registration Request to %s (Home Agent) " +
                     "using %s interface.", self._sent_reg_reqest.home_agent,
                     ifname)
        #logging.debug("care_of_address: %s, ifname: %s, prefixlen: %s",
        #              care_of_address, ifname, prefixlen)
        self._send_packet(self._sent_reg_reqest,
                          (self._sent_reg_reqest.home_agent, self.port))

        self._start_listening()
        self._lock.release()


    def _start_listening(self):
        self._listening = True

        # Staring listening for reply
        while self._listening and not self._closing:
            self._socket.settimeout(self.timeout) # Setting up timeout
            try:
                data, addr = self._socket.recvfrom(1024)
            except socket.timeout:
                self._handle_listening_timeout() # Timeout
            else:
                self._data_handler(data, addr) # Data received
        self._listening = False


    def _stop_listening(self):
        self._listening = False


    def cancel(self):
        """Cancel any ongoing registrations or registration attempts."""

        if self.is_registered():
            logging.info("Cancelling registration.")
            #_del_route(self.home_agent+"/32")
        self._closing = True
        if self._rereg_timer is not None:
            self._rereg_timer.cancel()
            self._rereg_timer = None
        self._destroy_tunnel()
        self._received_reg_reply = None
        self._sent_reg_reqest = None
        self._is_rereg = False
        self._gateway = None


class HomeAgent:
    """Mobile IP Home Agent class."""

    def __init__(self,
                 auth_table,
                 address="0.0.0.0",
                 port=434,
                 max_lifetime=INFINITE_LIFETIME, # Maximum acceptable Lifetime for registration
                 max_ident_mismatch=7, # Accepted timestamp mismatch in sec for identification
                 ip_pool="172.16.0.0/24"):
        """Home Agent constructor.

        Parameters:
        auth_table         -- dict that conctains SPIs as keys and
                              authorization KEYs as values
                              (e.g. {256: "1234567812345678"})
        address            -- Home Agent binding IP address (default is 0.0.0.0,
                              HA will listen on all network interfaces)
        port               -- Home Agent listening UDP port number (default is 434)
        max_lifetime       -- maximum acceptable Lifetime for registration
                              (default is INFINITE_LIFETIME)
        max_ident_mismatch -- accepted timestamp mismatch in seconds for
                              identification (default is 7)
        ip_pool            -- IP pool used for tunnel interfaces
                              (default is 172.16.0.0/24)
        """

        # Check if auth table is valid
        if len(auth_table) is 0:
            raise Error("Auth table is empty.")

        self.auth_table = auth_table
        self.address = address
        self.port = port
        self.max_lifetime = max_lifetime
        self.max_ident_mismatch = max_ident_mismatch
        self._ip_pool = IPNetwork(ip_pool)
        self._socket = None
        self._binding_table = {}
        self._binding_table_lock = threading.Lock()
        self._binding_checker = _BindingChecker(
            lock=self._binding_table_lock,
            binding_table=self._binding_table,
            lifetime_expired_handler=self._lifetime_expired_handler)


    def __del__():
        """Home Agent destructor"""

        _destroy_interfaces("mip") # Destroying all mipX interfaces
        set_ip_forward(False) # Disabling kernel IP forwarding
        set_proxy_arp_for_all(False) # Disabling Proxy ARP


    def _lifetime_expired_handler(self, reg_req_packet):
        """Handle registration expiration"""

        logging.warning("Binding [home address=%s, CoA=%s] has expired.",
                     reg_req_packet.home_address,
                     reg_req_packet.care_of_address)
        self._destroy_binding(reg_req_packet)


    def _print_binding_table(self):
        """Return registration binding table description."""

        desc = "{"
        for key, value in self._binding_table.iteritems():
            desc += "[home address=%s, CoA=%s]" % (key, value.care_of_address)
        return desc + "}"


    def _get_binding(self, home_address):
        """Return RegRequestPacket used in the registration for
        given Home address."""

        if home_address in self._binding_table:
            return self._binding_table[home_address]
        return None


    def _destroy_binding(self, reg_req_packet):
        """Destroy registration binding for given RegRequestPacket."""

        if reg_req_packet.home_address in self._binding_table:
            self._destroy_tunnel(reg_req_packet)
            self._binding_table_lock.acquire()
            logging.debug("Destroing [home address=%s, CoA=%s] binding.",
                         reg_req_packet.home_address,
                         reg_req_packet.care_of_address)
            del self._binding_table[reg_req_packet.home_address]
            self._binding_table_lock.release()
        else:
            logging.warning("Unable to find binding for home address=%s.",
                            home_address)


    def _create_binding(self, reg_req_packet):
        """Create registration binding for given RegRequestPacket."""

        # Computing new expiration date
        expiration_date = (0 if reg_req_packet.lifetime == INFINITE_LIFETIME
                           else time.time() + reg_req_packet.lifetime)

        # Handling existing binding
        existing_reg_req_packet = self._get_binding(reg_req_packet.home_address)
        if existing_reg_req_packet is not None:
            if existing_reg_req_packet.is_update_request(reg_req_packet):
                # reg_req_packet is an update, so updating only expiration_date
                logging.debug("Updating [home address=%s, CoA=%s] binding.",
                             existing_reg_req_packet.home_address,
                             existing_reg_req_packet.care_of_address)
                existing_reg_req_packet.expiration_date = expiration_date
                return
            # reg_req_packet is not an update, so destroying existing binding
            self._destroy_binding(existing_reg_req_packet)

        # Creating new binding
        self._binding_table_lock.acquire()
        logging.debug("Creating new binding [home address=%s, CoA=%s].",
                     reg_req_packet.home_address,
                     reg_req_packet.care_of_address)
        reg_req_packet.expiration_date = expiration_date
        self._binding_table[reg_req_packet.home_address] = reg_req_packet
        self._binding_table_lock.release()

        # Create tunnel
        self._create_tunnel(reg_req_packet)


    def _get_binding_id(self, home_address):
        """Return id of registration binding for given Home Address."""

        return self._binding_table.keys().index(home_address)


    def _create_tunnel(self, reg_req_packet):
        """Create GRE tunnel for given RegRequestPacket."""

        tid = self._get_binding_id(reg_req_packet.home_address)
        _create_tunnel(name="mip"+str(tid),
                       ip=str(self._ip_pool[tid+1]),
                       gre_local=self.address,
                       gre_remote=reg_req_packet.care_of_address,
                       route_dst=reg_req_packet.home_address+"/32")


    def _destroy_tunnel(self, reg_req_packet):
        """Destroy GRE tunnel for given RegRequestPacket."""

        tid = self._get_binding_id(reg_req_packet.home_address)
        _destroy_interface(name="mip"+str(tid))


    def _send_packet(self, packet, addr):
        """Send packet to given address."""

        logging.info("Sending: %s", packet)
        self._socket.sendto(packet.to_data(), addr)


    def _check_flags(self, flags):
        """Return True, if given flags are supported."""

        # Flags verification. Some capabilities are not implemented yet...
        # Only co-located care-of address are supported, so
        # D flag (Decapsulation by mobile node) is mandatory.
        # S (Simultaneous bindings) and B (Broadcast datagrams) are
        # not supported.
        # Only GRE tunnel is supported, so G is mandatory and M is not allowed.
        is_ok = True
        if not flags & RegRequestPacket.FLAG_D:
            logging.warning("D flag is not set but is mandatory.")
            is_ok = False
        if flags & RegRequestPacket.FLAG_S:
            logging.warning("S flag is set but is not supported.")
            is_ok = False
        if flags & RegRequestPacket.FLAG_B:
            logging.warning("B flag is set but is not supported.")
            is_ok = False
        if not flags & RegRequestPacket.FLAG_G:
            logging.warning("G flag is not set but is mandatory.")
            is_ok = False
        if flags & RegRequestPacket.FLAG_M:
            logging.warning("M flag is set but is not supported.")
            is_ok = False
        return is_ok


    def _data_handler(self, data, addr):
        """Handle received data."""

        in_packet = Packet.from_data(data)

        logging.debug("Connected by: %s", addr)
        logging.debug("Received: %s", in_packet)
        #logging.debug("Extensions:")
        #for extension in in_packet.extensions:
        #    logging.info(extension)

        if not isinstance(in_packet, RegRequestPacket):
            logging.warning("Invalid packet type has been received. " +
                           "Discarding packet.")
            return

        # Registration Request received
        logging.info("Registration Request has been received.")
        logging.debug("Bindings table: %s" , self._print_binding_table())

        # MHAE verification
        mhae = in_packet.get_mhae()
        if mhae is None or mhae.spi not in self.auth_table:
            # Can't find matching SPI, so silently discarding
            logging.warning("Can't find matching SPI in request. " +
                            "Discarding request.")
            return
        key = self.auth_table[mhae.spi]
        if not in_packet.verify_mhae(mhae.spi, key):
            # Authorization failed
            logging.warning("Reqest authorization is failed.")
            # Sending Registration Reply
            out_packet = RegReplyPacket(
                RegReplyPacket.CODE_MN_FAILED_AUTH,
                0x0000,
                in_packet.home_address,
                in_packet.home_agent,
                in_packet.identification)
            out_packet.add_mhae(mhae.spi, key)
            self._send_packet(out_packet, addr)
            return

        # Determining if duplicate
        existing_reg_req_packet = self._get_binding(in_packet.home_address)
        if existing_reg_req_packet is not None:
            if (existing_reg_req_packet.identification == in_packet.identification
                and existing_reg_req_packet.care_of_address == in_packet.care_of_address):
                logging.warning("Request is a retransmission. " +
                                "Discarding request.")
                return

        # Timestamp verification
        ha_time = time.time()
        mn_time = ntp_to_system_time(in_packet.identification)
        if abs(int(ha_time-mn_time)) > self.max_ident_mismatch:
            # Registration ID mismatch
            logging.warning("Registration identification is mismatch.")
            out_packet = RegReplyPacket(
                RegReplyPacket.CODE_IDENT_MISMATCH,
                0x0000,
                in_packet.home_address,
                in_packet.home_agent,
                in_packet.identification)
            out_packet.add_mhae(mhae.spi, key)
            self._send_packet(out_packet, addr)
            return

        # Flags verification
        if not self._check_flags(in_packet.flags):
            out_packet = RegReplyPacket(
                RegReplyPacket.CODE_DENIED_BY_HA,
                0x0000,
                in_packet.home_address,
                in_packet.home_agent,
                in_packet.identification)
            out_packet.add_mhae(mhae.spi, key)
            self._send_packet(out_packet, addr)
            return

        # Addresses verification
        if in_packet.care_of_address == in_packet.home_address:
            logging.warning("Care-of address is the same as home address. " +
                            "Mobile node is in the home network.")
            if in_packet.lifetime > 0:
                logging.error("Mobile node is in the home network, " +
                              "but registration is requested.")
                # TODO: Perhaps request should be rejected...

        # Registration Request accepted
        logging.info("Registration Request is valid.")

        # Updatig lifetime if lifetime > max_lifetime
        if in_packet.lifetime > self.max_lifetime:
            logging.warning("Requested lifetime is greater than maximum.")
            in_packet.lifetime = self.max_lifetime

        # Creating or destroying binding
        if in_packet.lifetime > 0:
            # Registration
            self._create_binding(in_packet)
        else:
            # Deregistration
            logging.info("Deregistration is requested.")
            self._destroy_binding(in_packet)

        # Sending Registration Reply
        out_packet = RegReplyPacket(
            RegReplyPacket.CODE_ACCEPTED,
            in_packet.lifetime,
            in_packet.home_address,
            in_packet.home_agent,
            in_packet.identification)
        out_packet.add_mhae(mhae.spi, key)
        self._send_packet(out_packet, addr)


    def start(self):
        """Start Home Agent server."""

        if self._socket is not None:
            logging.warning("Home Agent is already started.")
            return
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind((self.address, self.port))
        self._binding_checker.start()

        _destroy_interfaces("mip") # Destroying all mipX interfaces
        set_proxy_arp_for_all(True) # Enabling Proxy ARP
        set_ip_forward(True) # Enabling kernel IP forwarding

        logging.info("Home Agent is started.")
        while self._socket is not None:
            data, addr = self._socket.recvfrom(1024)
            self._data_handler(data, addr)


    def stop(self):
        """Stop Home Agent server."""

        self._stopping = True
        self._binding_checker.stop()

        _destroy_interfaces("mip") # Destroying all mipX interfaces
        set_ip_forward(False) # Disabling kernel IP forwarding
        set_proxy_arp_for_all(False) # Disabling Proxy ARP

        if self._socket is not None:
            self._socket.close()
            self._socket = None
            logging.info("Home Agent is stopped.")
        else:
            logging.warning("Home Agent is already stopped.")
