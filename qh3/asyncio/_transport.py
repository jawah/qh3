"""
Custom asyncio DatagramTransport with optimized UDP I/O.
"""

from __future__ import annotations

import asyncio
import socket
import struct
import sys
import typing
from collections import deque

# quinn-udp Rust syscall wrappers (always available, but instantiation
# raises NotImplementedError on non-Unix platforms).
from .._hazmat import UdpSocketState as _UdpSocketState

# Linux kernel constants for UDP segmentation offload.
UDP_GRO: typing.Final = 104
UDP_SEGMENT: typing.Final = 103

# struct formats for cmsg payloads (Python fallback path).
_UINT16: typing.Final = struct.Struct("=H")
_GRO_CMSG: typing.Final = struct.Struct("@i")

# Recv buffer sizing (Python fallback path).
_DEFAULT_GRO_BUF: typing.Final = 65535
_MAX_GRO_BUF: typing.Final = 262144

# Write flow-control watermarks.
_HIGH_WATERMARK: typing.Final = 64 * 1024
_LOW_WATERMARK: typing.Final = 16 * 1024

# GSO kernel limits (Python fallback path).
_GSO_MAX_SEGMENTS: typing.Final = 64
_GSO_MAX_PAYLOAD: typing.Final = 65000

# Bound recv burst per readiness callback.
_RECV_BURST_LIMIT: typing.Final = 32

_IS_LINUX: typing.Final = sys.platform == "linux"
_IS_UNIX: typing.Final = sys.platform != "win32"
_SOL_UDP: typing.Final = socket.SOL_UDP
_MSG_TRUNC: typing.Final = getattr(socket, "MSG_TRUNC", 0)
_MSG_CTRUNC: typing.Final = getattr(socket, "MSG_CTRUNC", 0)
_ANCBUFSIZE: typing.Final = socket.CMSG_SPACE(_GRO_CMSG.size)


def enable_gro(sock: socket.socket) -> bool:
    """Enable UDP GRO on *sock*. Returns True on success (Linux only)."""
    if not _IS_LINUX:
        return False
    try:
        sock.setsockopt(_SOL_UDP, UDP_GRO, 1)
        return sock.getsockopt(_SOL_UDP, UDP_GRO) == 1
    except OSError:
        return False


def has_gso(sock: socket.socket) -> bool:
    """Return True if the kernel supports UDP_SEGMENT on *sock* (Linux only)."""
    if not _IS_LINUX:
        return False
    try:
        sock.setsockopt(_SOL_UDP, UDP_SEGMENT, 1280)
        return bool(sock.getsockopt(_SOL_UDP, UDP_SEGMENT))
    except OSError:
        return False


def _parse_gro_segment_size(ancdata: list[tuple[int, int, bytes]]) -> int | None:
    for cmsg_level, cmsg_type, cmsg_data in ancdata:
        if cmsg_level == _SOL_UDP and cmsg_type == UDP_GRO:
            n = len(cmsg_data)
            if n >= _GRO_CMSG.size:
                return int(_GRO_CMSG.unpack_from(cmsg_data, 0)[0])
            if n >= _UINT16.size:
                return int(_UINT16.unpack_from(cmsg_data, 0)[0])
            return 0
    return None


def _split_gro_buffer(buf: bytes, segment_size: int) -> list[bytes]:
    n = len(buf)
    if segment_size <= 0 or n <= segment_size:
        return [buf]
    return [buf[i : i + segment_size] for i in range(0, n, segment_size)]


def _max_segments_for(size: int) -> int:
    if size <= 0:
        return _GSO_MAX_SEGMENTS
    cap = _GSO_MAX_PAYLOAD // size
    if cap < 1:
        return 1
    return cap if cap < _GSO_MAX_SEGMENTS else _GSO_MAX_SEGMENTS


def _group_for_gso(
    datagrams: list[bytes],
) -> list[tuple[int, list[bytes]]]:
    if not datagrams:
        return []
    groups: list[tuple[int, list[bytes]]] = []
    first = datagrams[0]
    current_size = len(first)
    current_group: list[bytes] = [first]
    cap = _max_segments_for(current_size)

    for dgram in datagrams[1:]:
        size = len(dgram)
        if size == current_size and len(current_group) < cap:
            current_group.append(dgram)
        elif size < current_size and len(current_group) < cap:
            current_group.append(dgram)
            groups.append((current_size, current_group))
            current_group = []
            current_size = 0
        else:
            if current_group:
                groups.append((current_size, current_group))
            current_size = size
            current_group = [dgram]
            cap = _max_segments_for(current_size)

    if current_group:
        groups.append((current_size, current_group))
    return groups


class OptimizedDatagramTransport(asyncio.DatagramTransport):
    """DatagramTransport that uses recvmmsg/sendmsg for GRO/GSO on Linux.

    When quinn-udp Rust is available, uses it for batched recvmmsg and
    GSO sendmsg. Falls back to Python recvmsg/sendmsg otherwise.
    """

    __slots__ = (
        "_loop",
        "_sock",
        "_sock_fd",
        "_protocol",
        "_address",
        "_gro_enabled",
        "_gso_enabled",
        "_gro_segment_size",
        "_recv_buf_size",
        "_closing",
        "_closed",
        "_paused",
        "_extra",
        "_send_queue",
        "_buffer_size",
        "_protocol_paused",
        "_writer_registered",
        "_reader_registered",
        "_protocol_supports_batch",
        "_udp_state",
    )

    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        sock: socket.socket,
        protocol: asyncio.DatagramProtocol,
        address: tuple[str, int] | None,
        gro_enabled: bool,
        gso_enabled: bool,
        gro_segment_size: int,
    ) -> None:
        super().__init__()
        self._loop = loop
        self._sock = sock
        self._sock_fd = sock.fileno()
        self._protocol = protocol
        self._address = address
        self._gro_enabled = gro_enabled
        self._gso_enabled = gso_enabled
        self._gro_segment_size = gro_segment_size
        self._closing = False
        self._closed = False
        self._paused = False
        self._writer_registered = False
        self._reader_registered = False
        self._send_queue: deque[tuple[bytes, typing.Any]] = deque()
        self._buffer_size = 0
        self._protocol_paused = False
        self._protocol_supports_batch = hasattr(protocol, "datagrams_received")

        self._recv_buf_size = (
            _DEFAULT_GRO_BUF if gro_enabled else max(gro_segment_size, 1500)
        )

        # Try to create quinn-udp state for fast Rust syscalls.
        # Works on all Unix (Linux: recvmmsg+GRO, macOS: recvmsg_x).
        # Raises NotImplementedError on non-Unix platforms.
        self._udp_state: typing.Any = None
        try:
            self._udp_state = _UdpSocketState(self._sock_fd)
        except Exception:
            pass

        try:
            sockname = sock.getsockname()
        except OSError:
            sockname = None

        self._extra = {
            "peername": address,
            "socket": sock,
            "sockname": sockname,
            "family": sock.family,
            "type": sock.type,
        }

    def get_extra_info(self, name: str, default: typing.Any = None) -> typing.Any:
        return self._extra.get(name, default)

    def is_closing(self) -> bool:
        return self._closing

    def get_protocol(self) -> asyncio.BaseProtocol:
        return self._protocol

    def set_protocol(self, protocol: asyncio.BaseProtocol) -> None:
        self._protocol = protocol  # type: ignore[assignment]
        self._protocol_supports_batch = hasattr(protocol, "datagrams_received")

    def get_write_buffer_size(self) -> int:
        return self._buffer_size

    def close(self) -> None:
        if self._closing:
            return
        self._closing = True
        self._unregister_reader()
        if not self._send_queue:
            self._loop.call_soon(self._call_connection_lost, None)

    def abort(self) -> None:
        if self._closing:
            return
        self._closing = True
        self._send_queue.clear()
        self._buffer_size = 0
        self._loop.call_soon(self._call_connection_lost, None)

    def _call_connection_lost(self, exc: Exception | None) -> None:
        if self._closed:
            return
        self._closed = True
        self._unregister_reader()
        self._unregister_writer()
        try:
            self._protocol.connection_lost(exc)
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException:
            pass
        finally:
            self._udp_state = None
            try:
                self._sock.close()
            except OSError:
                pass

    def _register_reader(self) -> None:
        if self._reader_registered or self._closed:
            return
        try:
            self._loop.add_reader(self._sock_fd, self._on_readable)
            self._reader_registered = True
        except (OSError, ValueError):
            pass

    def _unregister_reader(self) -> None:
        if not self._reader_registered:
            return
        self._reader_registered = False
        try:
            self._loop.remove_reader(self._sock_fd)
        except (OSError, ValueError):
            pass

    def _register_writer(self) -> None:
        if self._writer_registered or self._closed:
            return
        try:
            self._loop.add_writer(self._sock_fd, self._on_write_ready)
            self._writer_registered = True
        except (OSError, ValueError):
            pass

    def _unregister_writer(self) -> None:
        if not self._writer_registered:
            return
        self._writer_registered = False
        try:
            self._loop.remove_writer(self._sock_fd)
        except (OSError, ValueError):
            pass

    def pause_reading(self) -> None:
        if not self._paused:
            self._paused = True
            self._unregister_reader()

    def resume_reading(self) -> None:
        if self._paused:
            self._paused = False
            self._register_reader()

    def _raw_send(self, data: bytes, addr: typing.Any) -> None:
        if addr is not None:
            self._sock.sendto(data, addr)
        elif self._address is not None:
            self._sock.sendto(data, self._address)
        else:
            self._sock.send(data)

    def sendto(self, data: bytes, addr: typing.Any = None) -> None:
        if self._closing:
            return

        if self._send_queue:
            self._queue_write(data, addr)
            return

        try:
            self._raw_send(data, addr)
        except BlockingIOError:
            self._register_writer()
            self._queue_write(data, addr)
        except OSError as exc:
            self._protocol.error_received(exc)

    def sendto_many(self, datagrams: list[bytes], addr: typing.Any = None) -> None:
        """Send multiple datagrams, using GSO when available."""
        if self._closing or not datagrams:
            return

        if self._send_queue:
            for dgram in datagrams:
                self._queue_write(dgram, addr)
            return

        # Prefer Rust quinn-udp send (handles GSO internally when available,
        # falls back to per-datagram sendmsg on platforms without GSO).
        state = self._udp_state
        if state is not None:
            target = addr if addr is not None else self._address
            if target is not None:
                try:
                    state.send(datagrams, str(target[0]), int(target[1]))
                    return
                except BlockingIOError:
                    self._register_writer()
                    for dgram in datagrams:
                        self._queue_write(dgram, addr)
                    return
                except OSError:
                    # Fall through to Python path.
                    pass

        if self._gso_enabled:
            self._send_gso_python(datagrams, addr)
        else:
            for dgram in datagrams:
                self.sendto(dgram, addr)
                if self._closing or self._closed:
                    return

    def _send_gso_python(self, datagrams: list[bytes], addr: typing.Any) -> None:
        """Python fallback: sendmsg with UDP_SEGMENT cmsg."""
        groups = _group_for_gso(datagrams)
        sock = self._sock
        target = addr if addr is not None else self._address

        for i, (segment_size, group) in enumerate(groups):
            try:
                if len(group) == 1:
                    self._raw_send(group[0], addr)
                else:
                    if target is not None:
                        sock.sendmsg(
                            group,
                            [(_SOL_UDP, UDP_SEGMENT, _UINT16.pack(segment_size))],
                            0,
                            target,
                        )
                    else:
                        sock.sendmsg(
                            group,
                            [(_SOL_UDP, UDP_SEGMENT, _UINT16.pack(segment_size))],
                        )
            except BlockingIOError:
                self._register_writer()
                for _sz, g in groups[i:]:
                    for dgram in g:
                        self._queue_write(dgram, addr)
                return
            except OSError as exc:
                if len(group) > 1:
                    for dgram in group:
                        try:
                            self._raw_send(dgram, addr)
                        except BlockingIOError:
                            self._register_writer()
                            self._queue_write(dgram, addr)
                            idx = group.index(dgram) + 1
                            for tail in group[idx:]:
                                self._queue_write(tail, addr)
                            for _sz, g in groups[i + 1 :]:
                                for d in g:
                                    self._queue_write(d, addr)
                            return
                        except OSError as inner:
                            self._protocol.error_received(inner)
                            if self._closing or self._closed:
                                return
                else:
                    self._protocol.error_received(exc)
                    if self._closing or self._closed:
                        return

    def _queue_write(self, data: bytes, addr: typing.Any) -> None:
        self._send_queue.append((data, addr))
        self._buffer_size += len(data)
        if self._buffer_size >= _HIGH_WATERMARK and not self._protocol_paused:
            self._protocol_paused = True
            try:
                self._protocol.pause_writing()
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException:
                pass

    def _on_write_ready(self) -> None:
        queue = self._send_queue
        raw_send = self._raw_send

        while queue:
            data, addr = queue[0]
            try:
                raw_send(data, addr)
            except BlockingIOError:
                return
            except InterruptedError:
                continue
            except OSError as exc:
                queue.popleft()
                self._buffer_size -= len(data)
                self._maybe_resume_protocol()
                try:
                    self._protocol.error_received(exc)
                except (KeyboardInterrupt, SystemExit):
                    raise
                except BaseException:
                    pass
                if self._closing or self._closed:
                    break
                continue

            queue.popleft()
            self._buffer_size -= len(data)
            self._maybe_resume_protocol()

        if not queue:
            self._unregister_writer()
            if self._closing and not self._closed:
                self._loop.call_soon(self._call_connection_lost, None)

    def _maybe_resume_protocol(self) -> None:
        if self._protocol_paused and self._buffer_size <= _LOW_WATERMARK:
            self._protocol_paused = False
            try:
                self._protocol.resume_writing()
            except (KeyboardInterrupt, SystemExit):
                raise
            except BaseException:
                pass

    def _start(self, waiter: asyncio.Future[None] | None = None) -> None:
        self._loop.call_soon(self._protocol.connection_made, self)
        self._loop.call_soon(self._register_reader)
        if waiter is not None:
            self._loop.call_soon(waiter.set_result, None)

    def _on_readable(self) -> None:
        if self._closing:
            return
        # Prefer Rust quinn-udp
        state = self._udp_state
        if state is not None:
            self._recv_rust(state)
        elif self._gro_enabled:
            self._recv_gro_python()
        else:
            self._recv_plain()

    def _recv_rust(self, state: typing.Any) -> None:
        """Batch-receive via quinn-udp Rust."""
        protocol = self._protocol
        batch_cb = (
            protocol.datagrams_received  # type: ignore[attr-defined]
            if self._protocol_supports_batch
            else None
        )
        _recv = state.recv
        hit_limit = False

        if batch_cb is not None:
            # Accumulate all segments across recv calls, deliver once.
            all_segments: list[bytes] = []
            addr: typing.Any = None
            for _ in range(_RECV_BURST_LIMIT):
                try:
                    segments, a = _recv()
                except OSError:
                    break
                if not segments:
                    break
                all_segments.extend(segments)
                addr = a
            else:
                hit_limit = True
            if all_segments:
                batch_cb(all_segments, addr)
        else:
            datagram_received = protocol.datagram_received
            for _ in range(_RECV_BURST_LIMIT):
                try:
                    segments, addr = _recv()
                except OSError:
                    return
                if not segments:
                    return
                for seg in segments:
                    datagram_received(seg, addr)
            else:
                hit_limit = True

        # Hit burst limit
        # yield and reschedule.
        if hit_limit and not self._closing and self._reader_registered:
            self._loop.call_soon(self._on_readable)

    def _recv_plain(self) -> None:
        sock = self._sock
        protocol = self._protocol
        for _ in range(_RECV_BURST_LIMIT):
            try:
                data, addr = sock.recvfrom(65536)
            except BlockingIOError:
                return
            except InterruptedError:
                continue
            except OSError as exc:
                protocol.error_received(exc)
                return
            if not data:
                return
            protocol.datagram_received(data, addr)

    def _recv_gro_python(self) -> None:
        """Python fallback: recvmsg with GRO cmsg parsing."""
        sock_recvmsg = self._sock.recvmsg
        protocol = self._protocol
        datagram_received = protocol.datagram_received
        batch_cb = (
            protocol.datagrams_received  # type: ignore[attr-defined]
            if self._protocol_supports_batch
            else None
        )
        default_segment_size = self._gro_segment_size
        ancbufsize = _ANCBUFSIZE

        for _ in range(_RECV_BURST_LIMIT):
            try:
                data, ancdata, flags, addr = sock_recvmsg(
                    self._recv_buf_size, ancbufsize
                )
            except BlockingIOError:
                return
            except InterruptedError:
                continue
            except OSError as exc:
                try:
                    protocol.error_received(exc)
                except (KeyboardInterrupt, SystemExit):
                    raise
                except BaseException:
                    pass
                return

            if not data:
                return

            if flags & _MSG_TRUNC:
                bufsize = self._recv_buf_size
                if bufsize < _MAX_GRO_BUF:
                    self._recv_buf_size = min(bufsize * 2, _MAX_GRO_BUF)
                continue

            if flags & _MSG_CTRUNC:
                datagram_received(data, addr)
                continue

            parsed = _parse_gro_segment_size(ancdata)
            if parsed is None:
                datagram_received(data, addr)
                continue

            segment_size = parsed if parsed > 0 else default_segment_size
            if len(data) <= segment_size:
                datagram_received(data, addr)
                continue

            segments = _split_gro_buffer(data, segment_size)
            if batch_cb is not None:
                batch_cb(segments, addr)
            else:
                for seg in segments:
                    datagram_received(seg, addr)

        if not self._closing and self._reader_registered:
            self._loop.call_soon(self._on_readable)


async def create_optimized_datagram_transport(
    loop: asyncio.AbstractEventLoop,
    protocol_factory: typing.Callable[[], asyncio.DatagramProtocol],
    sock: socket.socket,
    gro_segment_size: int = 1280,
) -> tuple[asyncio.DatagramTransport, asyncio.DatagramProtocol]:
    """Create a DatagramTransport with optimized UDP I/O if available."""
    gro_enabled = enable_gro(sock)
    gso_enabled = has_gso(sock)

    # Use custom transport on Unix (GRO/GSO on Linux, quinn-udp recv/send
    # on all Unix).  On Windows the ProactorEventLoop does not support
    # add_reader(), so we must fall back to the stock asyncio transport.
    if not _IS_UNIX and not gro_enabled and not gso_enabled:
        return await loop.create_datagram_endpoint(protocol_factory, sock=sock)

    sock.setblocking(False)
    protocol = protocol_factory()
    transport = OptimizedDatagramTransport(
        loop=loop,
        sock=sock,
        protocol=protocol,
        address=None,
        gro_enabled=gro_enabled,
        gso_enabled=gso_enabled,
        gro_segment_size=gro_segment_size,
    )
    waiter = loop.create_future()
    transport._start(waiter)
    await waiter
    return transport, protocol
