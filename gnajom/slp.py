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
from struct import pack, unpack
import sys


PROTOCOL_LATEST = 0x4a
PING_KEYWORD = "MC|PingHost"


def pack_str(buf, s):
    buf.write(pack(">H", len(s)))
    buf.write(s.encode("utf_16_be"))


def pack_ping(buf, hostname, port, protocol_version=PROTOCOL_LATEST):
    tmp = StringIO()
    tmp.write(pack(">B", protocol_version))
    compose_str(tmp, hostname)
    tmp.write(pack(">I", port))
    tail = tmp.getvalue()
    tmp.close()

    buf.write(pack(">BBB", 0xFE, 0x01, 0xFE))
    compose_str(buf, PING_KEYWORD)
    buf.write(pack(">H", len(tail)))
    buf.write(tail)


def unpack_kick(buf):
    pass


#
# The end.
