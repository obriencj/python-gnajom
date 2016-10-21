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
gnajom - Python package for querying Minecraft servers

:author: Christopher O'Brien <obriencj@gmail.com>
:license: LGPL v3
"""


from struct import pack, unpack, Struct

_B = Struct(">B")


def pack_varint(buf, val):
    p = _B.pack

    if val < 0:
	val = (1<<32) + val

    while val >= 0x80:
	bits = val & 0x7F
        b, _ = p(0x80 | bits)
	buf.write(b)

	val >>= 7
	bits = val & 0x7F
        b, _ = p(bits)
        buf.write(b)


def unpack_varint(buf):
    u = _B.unpack

    total = 0
    shift = 0
    val = 0x80

    while val & 0x80:
        val, _ = u(buf.read(1))
        total |= ((val & 0x7f) << shift)
        shift += 7

    if total & (1<<31):
        total = total - (1<<32)

    return total


#
# The end.
