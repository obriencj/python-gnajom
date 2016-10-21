# This library is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, see
# <http://www.gnu.org/licenses/>.


"""
gnajom.slp - Python package for working with Minecraft via the Server
List Ping portion of the protocol

:author: Christopher O'Brien <obriencj@gmail.com>
:license: LGPL v3
"""


from cStringIO import StringIO
from socket import socket
from struct import pack, unpack
import sys


PROTOCOL_LATEST = 0x4a
PING_KEYWORD = "MC|PingHost"


def pack_str(buf, s):
    buf.write(pack(">H", len(s)))
    buf.write(s.encode("utf_16_be"))


def pack_legacy_ping(buf, hostname, port, protocol_version=PROTOCOL_LATEST):
    tmp = StringIO()
    tmp.write(pack(">B", protocol_version))
    pack_str(tmp, hostname)
    tmp.write(pack(">I", port))
    tail = tmp.getvalue()
    tmp.close()

    buf.write(pack(">BBB", 0xFE, 0x01, 0xFE))
    pack_str(buf, PING_KEYWORD)
    buf.write(pack(">H", len(tail)))
    buf.write(tail)


def unpack_legacy_kick(stream):
    """
    unpacks a legacy kick message from a stream, returns a tuple of
    (protocol version, server version, motd, online players, max players)

    If the message is the wrong type, or the data is malformed, raises
    InvalidSLPResponse
    """

    buf = stream.read(3)
    check, length = unpack(">BH", buf)
    if check != 0xff:
        raise InvalidSLPResponse("package type %i" % (check))

    remainder = stream.read(length).decode("utf_16_be")
    fields = remainder.split("\0")

    if fields[0] != "\xa7\x31":
        raise InavlidSLPResponse("field heading %r" % fields[0])

    check, proto_ver, ser_ver, motd, online, maxonline = fields
    online = ord(online)
    maxonline = ord(maxonline)

    return proto_ver, ser_ver, motd, online, maxonline


def legacy_slp(host, port, protocol_version=PROTOCOL_LATEST):
    print "connecting to %s %i..." % (host, port),
    sock = socket()
    sock.connect((host, port))
    print "connected"

    sockf = sock.makefile()

    print "sending SLP...",
    pack_legacy_ping(sockf, host, port, protocol_version)
    print "done"

    print "seceiving kick...",
    fields = unpack_legacy_kick(sockf)
    print "done"

    sock.close()
    print "socket closed"

    return fields


#
# The end.
