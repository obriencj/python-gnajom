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
gnajom - Python package for composing and unpacking data in the Minecraft
server protocol

:author: Christopher O'Brien <obriencj@gmail.com>
:license: LGPL v3
"""


import socket
import zlib

from cStringIO import StringIO
from functools import update_wrapper
from singledispatch import singledispatch
from struct import Struct


PROTOCOL_LATEST = 0x4a


_B = Struct(">B")
_H = Struct(">H")


_PACKET_PACKERS = {}
_PACKET_UNPACKERS = {}


class ProtocolException(Exception):
    pass


class ProtocolUnpackException(ProtocolException):
    pass


# --- Packing and Unpacking Functions ---


def read_or_raise(stream, count, exc_class):
    data = stream.read(count)
    dlen = len(data)
    if data and dlen == count:
        return data
    else:
        raise exc_class("wanted %i bytes, read %i", (count, dlen))


def pack_string(stream, s):
    dat, _ = _H.pack(len(s))
    stream.write(dat)
    stream.write(s.encode("utf_16_be"))


def pack_struct(stream, defn, *values):
    dat, _ = defn.pack(*values)
    stream.write(dat)


def pack_varint(stream, val):
    p = _B.pack

    if val < 0:
        val = (1 << 32) + val

    while val >= 0x80:
        bits = val & 0x7F
        b, _ = p(0x80 | bits)
        stream.write(b)

        val >>= 7
        bits = val & 0x7F
        b, _ = p(bits)
        stream.write(b)


def unpack_varint(stream):
    u = _B.unpack

    total = 0
    shift = 0
    val = 0x80

    while val & 0x80:
        val, _ = u(stream.read(1))
        total |= ((val & 0x7f) << shift)
        shift += 7

    if total & (1 << 31):
        total = total - (1 << 32)

    return total


def receive_packet(stream, state, compressed=False, raw=False):
    length = unpack_varint(stream)

    buf = read_or_raise(stream, length, ProtocolUnpackException)
    if compressed:
        # re-read the new length value for the uncompressed data
        length = unpack_varint(stream)
        buf = StringIO(zlib.decompress(buf))
    else:
        buf = StringIO(buf)

    packet_id = unpack_varint(buf)
    if raw:
        # don't continue unpacking, just return the packet ID and the
        # data glob
        return packet_id, buf.read()

    else:
        packet = ProtocolPacket.for_packet_id(state, packet_id)
        packet.unpack(buf)
        return packet


def send_packet(stream, packet, compress=False, raw=False):
    if raw:
        # in raw mode, the packet is just a tuple of an ID and the
        # serialized data.

        packet_id, data = packet
        buf = StringIO()
        pack_varint(buf, packet_id)
        buf.write(data)
        data = buf.getvalue()
        buf.close()

    else:
        # otherwise, the packet is an actual ProtocolPacket instance,
        # and we can get the data from that

        packet_id = packet.PACKET_ID
        buf = StringIO()
        pack_varint(buf, packet_id)
        packet.pack(buf)
        data = buf.getvalue()
        buf.close()

    if compress:
        length = len(data)
        data = zlib.compress(data)

        buf = StringIO()
        pack_varint(buf, length)
        buf.write(data)
        data = buf.getvalue()
        buf.close()

    pack_varint(len(data))
    stream.write(data)


def dispatch(func):
    dispatcher = singledispatch(func)

    def wrapper(self, *args, **kw):
        return dispatcher.dispatch(args[0].__class__)(self, *args, **kw)

    wrapper.register = dispatcher.register
    update_wrapper(wrapper, func)
    return wrapper


# --- Session State Definitions ---


STATE_CLOSED = -2
STATE_CONNECTED = -1
STATE_HANDSHAKING = 0
STATE_STATUS = 1
STATE_LOGIN = 2
STATE_PLAY = 3

SESSION_STATES = {
    STATE_CLOSED: "Closed",
    STATE_CONNECTED: "Connected",
    STATE_HANDSHAKING: "Handshaking",
    STATE_STATUS: "Status",
    STATE_LOGIN: "Login",
    STATE_PLAY: "Play"
}


class ClientStateException(Exception):
    def __init__(self, expected_state, actual_state):
        self.expected_state = expected_state
        self.actual_state = actual_state
        super(self, ClientStateException).__init__(self, expected_state,
                                                   actual_state)


# --- Protocol Packets ---


class ProtocolPacketMeta(type):
    CLIENTBOUND_PACKET_IDS = {}
    SERVERBOUND_PACKET_IDS = {}

    def __init__(cls, name, bases, class_dict):
        if "PACKET_STATE" not in class_dict:
            return
        if "PACKET_ID" not in class_dict:
            return

        new_packet_state = class_dict["PACKET_STATE"]
        new_packet_id = class_dict["PACKET_ID"]
        new_packet_key = (new_packet_state, new_packet_id)

        if issubclass(cls, ClientboundPacket):
            packet_ids = ProtocolPacketMeta.CLIENTBOUND_PACKET_IDS
            assert(new_packet_key not in packet_ids)
            packet_ids[new_packet_key] = cls

        if issubclass(cls, ServerboundPacket):
            packet_ids = ProtocolPacketMeta.SERVERBOUND_PACKET_IDS
            assert(new_packet_key not in packet_ids)
            packet_ids[new_packet_key] = cls

    @staticmethod
    def for_clientbound_packet_id(state_packet_id):
        packet_ids = ProtocolPacketMeta.CLIENTBOUND_PACKET_IDS
        pclass = packet_ids[state_packet_id]
        return ProtocolPacket.__new__(pclass)

    @staticmethod
    def for_serverbound_packet_id(state_packet_id):
        packet_ids = ProtocolPacketMeta.SERVERBOUND_PACKET_IDS
        pclass = packet_ids[state_packet_id]
        return ProtocolPacket.__new__(pclass)


class ProtocolPacket(object):
    __metaclass__ = ProtocolPacketMeta


class ClientboundPacket(ProtocolPacket):

    def unpack(self, stream):
        raise NotImplemented(type(self).__name__)


class ServerboundPacket(ProtocolPacket):

    def pack(self, stream):
        raise NotImplemented(type(self).__name__)


# --- Serverbound Packet Definitions ---


class Handshake(ServerboundPacket):
    """
    http://wiki.vg/Protocol#Handshaking
    """

    PACKET_STATE = STATE_HANDSHAKING
    PACKET_ID = 0x00
    PACKET_NAME = "Handshake"


    def __init__(self, protocol_version, server_address,
                 server_port, next_state):

        self.protocol_version = protocol_version
        self.server_address = server_address
        self.server_port = server_port
        self.next_state = next_state


    def pack(self, stream):
        pack_varint(stream, self.packet_id)
        pack_varint(stream, self.protocol_version)
        pack_string(stream, self.server_address)
        pack_struct(stream, ">b", self.server_port)
        pack_varint(stream, self.next_state)


class Request(ServerboundPacket):
    PACKET_STATE = STATE_STATUS
    PACKET_ID = 0x00
    PACKET_NAME = "Request"


class Ping(ServerboundPacket):
    PACKET_STATE = STATE_STATUS
    PACKET_ID = 0x01
    PACKET_NAME = "Ping"


class LoginStart(ServerboundPacket):
    PACKET_STATE = STATE_LOGIN
    PACKET_ID = 0x00
    PACKET_NAME = "Login Start"


class EncruptionResponse(ServerboundPacket):
    PACKET_STATE = STATE_LOGIN
    PACKET_ID = 0x01
    PACKET_NAME = "Encruption Request"


# --- Clientbound Packet Definitions ---


class Response(ClientboundPacket):
    PACKET_STATE = STATE_STATUS
    PACKET_ID = 0x00
    PACKET_NAME = "Response"


class Pong(ClientboundPacket):
    PACKET_STATE = STATE_STATUS
    PACKET_ID = 0x01
    PACKET_NAME = "Pong"


class Disconnect(ClientboundPacket):
    PACKET_STATE = STATE_LOGIN
    PACKET_ID = 0x00
    PACKET_NAME = "Disconnect"

    def unpack(self, stream):
        pass


class EncryptionRequest(ClientboundPacket):
    PACKET_STATE = STATE_LOGIN
    PACKET_ID = 0x01
    PACKET_NAME = "Encryption Request"

    def unpack(self, stream):
        pass


class LoginSuccess(ClientboundPacket):
    PACKET_STATE = STATE_LOGIN
    PACKET_ID = 0x02
    PACKET_NAME = "Login Success"

    def unpack(self, stream):
        pass


class SetCompression(ClientboundPacket):
    PACKET_STATE = STATE_LOGIN
    PACKET_ID = 0x03
    PACKET_NAME = "Set Compression"

    def unpack(self, stream):
        pass


# --- Client Session Implementation ---


class ClientSession(object):

    def __init__(self):
        self.state = STATE_CLOSED
        self.compression = False
        self.stream = None


    def open(self, host, port):
        if self.state != STATE_CLOSED:
            raise ClientStateException(STATE_CLOSED, self.state)

        self.stream = socket.socket(host, port)
        self.state = STATE_CONNECTED


    def handshake(self):
        if self.state != STATE_CONNECTED:
            raise ClientStateException(STATE_CONNECTED, self.state)


    def send(self, packet):
        send_packet(self.stream, packet, compressed=self.compression)


    def receive(self):
        return receive_packet(self.stream, self.state,
                              compressed=self.compression)


    def receive_and_handle(self):
        return self.handle(self.receive())


    @dispatch
    def handle(self, packet):
        raise NotImplemented("no handler for %r" % type(packet))


    @handle.register(Response)
    def _handle_response(self, packet):
        pass


    @handle.register(Disconnect)
    def _handle_disconnect(self, packet):
        pass


    @handle.register(EncryptionRequest)
    def _handle_encrequest(self, packet):
        pass


    @handle.register(LoginSuccess)
    def _handle_loginsuccess(self, packet):
        pass


    @handle.register(SetCompression)
    def _handle_setcompress(self, packet):
        pass


#
# The end.
