
import socket
import asyncio

import dns._asyncbackend
import dns.exception
from dns._asyncio_backend import _get_running_loop, _maybe_wait_for, _DatagramProtocol, DatagramSocket,StreamSocket,Backend as AsyncioBackend


class _AsyncioDatagramProtocol(_DatagramProtocol):
    def __init__(self):
        self.transport = None
        self.recvfrom = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if self.recvfrom:
            self.recvfrom.set_result((data, addr))
            self.recvfrom = None

    def error_received(self, exc):  # pragma: no cover
        if self.recvfrom and not self.recvfrom.done():
            try:
                self.recvfrom.set_exception(exc)
            except asyncio.InvalidStateError:
                print("running")

    def connection_lost(self, exc):
        if self.recvfrom and not self.recvfrom.done():
            try:
                self.recvfrom.set_exception(exc)
            except asyncio.InvalidStateError:
                print("running")

    def close(self):
        self.transport.close()



class Backend(AsyncioBackend):
    async def make_socket(self, af, socktype, proto=0,
                          source=None, destination=None, timeout=None,
                          ssl_context=None, server_hostname=None):
        loop = _get_running_loop()
        if socktype == socket.SOCK_DGRAM:
            transport, protocol = await loop.create_datagram_endpoint(
                _AsyncioDatagramProtocol, source, family=af,
                proto=proto)
            return DatagramSocket(af, transport, protocol)
        elif socktype == socket.SOCK_STREAM:
            (r, w) = await _maybe_wait_for(
                asyncio.open_connection(destination[0],
                                        destination[1],
                                        ssl=ssl_context,
                                        family=af,
                                        proto=proto,
                                        local_addr=source,
                                        server_hostname=server_hostname),
                timeout)
            return StreamSocket(af, r, w)
        raise NotImplementedError('unsupported socket ' +
                                  f'type {socktype}')  # pragma: no cover