"""Pure-stdlib synthetic capture builder for the OTscope regression suite.

Writes classic libpcap files (Ethernet link type) with correct IPv4, TCP,
and UDP checksums so tshark dissects them like real traffic.  No third-party
packages and no real capture data: every scenario is generated at test time
into a temporary directory and never committed.
"""

from __future__ import annotations

import random
import struct
from typing import Dict, List, Optional, Tuple

LINKTYPE_ETHERNET = 1
TCP_FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10}


def _inet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def _mac(mac: str) -> bytes:
    return bytes(int(part, 16) for part in mac.split(":"))


def _ip(ip: str) -> bytes:
    return bytes(int(part) for part in ip.split("."))


def multicast_mac(ip: str) -> str:
    octets = [int(part) for part in ip.split(".")]
    return "01:00:5e:%02x:%02x:%02x" % (octets[1] & 0x7F, octets[2], octets[3])


class Net:
    """Collects frames for one capture file."""

    def __init__(self, seed: int = 7, start: float = 1760000000.0) -> None:
        self.rng = random.Random(seed)
        self.t0 = start
        self.frames: List[Tuple[float, bytes]] = []
        self._macs: Dict[str, str] = {}
        self._ipid: Dict[str, int] = {}
        self._next_mac = 0x10

    # -- addressing -------------------------------------------------------
    def mac(self, ip: str) -> str:
        if ip not in self._macs:
            self._next_mac += 1
            self._macs[ip] = "02:00:00:00:%02x:%02x" % ((self._next_mac >> 8) & 0xFF, self._next_mac & 0xFF)
        return self._macs[ip]

    def set_mac(self, ip: str, mac: str) -> None:
        self._macs[ip] = mac

    def _next_ipid(self, ip: str) -> int:
        self._ipid[ip] = (self._ipid.get(ip, self.rng.randint(1, 30000)) + 1) & 0xFFFF
        return self._ipid[ip]

    # -- frame builders ---------------------------------------------------
    def _ipv4(self, src: str, dst: str, proto: int, l4: bytes, ttl: int) -> bytes:
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), self._next_ipid(src), 0x4000,
                             ttl, proto, 0, _ip(src), _ip(dst))
        header = header[:10] + struct.pack("!H", _inet_checksum(header)) + header[12:]
        return header + l4

    def _l4_checksum(self, src: str, dst: str, proto: int, segment: bytes) -> int:
        pseudo = _ip(src) + _ip(dst) + struct.pack("!BBH", 0, proto, len(segment))
        return _inet_checksum(pseudo + segment)

    def emit(self, ts: float, src_mac: str, dst_mac: str, ethertype: int, payload: bytes) -> None:
        self.frames.append((ts, _mac(dst_mac) + _mac(src_mac) + struct.pack("!H", ethertype) + payload))

    def ip_packet(self, ts: float, src: str, dst: str, proto: int, l4: bytes, ttl: int = 64,
                  dst_mac: Optional[str] = None) -> None:
        self.emit(ts, self.mac(src), dst_mac or self.mac(dst), 0x0800, self._ipv4(src, dst, proto, l4, ttl))

    def tcp(self, ts: float, src: str, sport: int, dst: str, dport: int, seq: int, ack: int,
            flags: str, payload: bytes = b"", ttl: int = 64) -> None:
        bits = 0
        for flag in flags:
            bits |= TCP_FLAG_BITS[flag]
        header = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                             5 << 4, bits, 64240, 0, 0)
        segment = header + payload
        csum = self._l4_checksum(src, dst, 6, segment)
        segment = segment[:16] + struct.pack("!H", csum) + segment[18:]
        self.ip_packet(ts, src, dst, 6, segment, ttl=ttl)

    def udp(self, ts: float, src: str, sport: int, dst: str, dport: int, payload: bytes,
            dst_mac: Optional[str] = None) -> None:
        segment = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
        csum = self._l4_checksum(src, dst, 17, segment) or 0xFFFF
        segment = segment[:6] + struct.pack("!H", csum) + segment[8:]
        if dst_mac is None and int(dst.split(".")[0]) >= 224:
            dst_mac = multicast_mac(dst)
        self.ip_packet(ts, src, dst, 17, segment, dst_mac=dst_mac)

    def icmp_echo(self, ts: float, src: str, dst: str, ident: int, seq: int, reply: bool = False) -> None:
        body = struct.pack("!BBHHH", 0 if reply else 8, 0, 0, ident, seq) + b"abcdefghijklmnopqrstuvwabcdefghi"
        body = body[:2] + struct.pack("!H", _inet_checksum(body)) + body[4:]
        self.ip_packet(ts, src, dst, 1, body)

    def arp(self, ts: float, op: int, sender_mac: str, sender_ip: str, target_ip: str,
            target_mac: str = "00:00:00:00:00:00", eth_src: Optional[str] = None,
            eth_dst: str = "ff:ff:ff:ff:ff:ff") -> None:
        body = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, op, _mac(sender_mac), _ip(sender_ip),
                           _mac(target_mac), _ip(target_ip))
        self.emit(ts, eth_src or sender_mac, eth_dst, 0x0806, body)

    # -- sessions ---------------------------------------------------------
    def session(self, client: str, cport: int, server: str, sport: int) -> "TcpSession":
        return TcpSession(self, client, cport, server, sport)

    # -- output -----------------------------------------------------------
    def write(self, path: str, truncate_tail: int = 0) -> None:
        frames = sorted(self.frames, key=lambda item: item[0])
        out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for ts, frame in frames:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            if usec >= 1_000_000:
                sec, usec = sec + 1, usec - 1_000_000
            out += struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
        if truncate_tail:
            out = out[:-truncate_tail]
        with open(path, "wb") as handle:
            handle.write(bytes(out))


class TcpSession:
    """A TCP conversation with consistent sequence/ack numbers."""

    def __init__(self, net: Net, client: str, cport: int, server: str, sport: int) -> None:
        self.net, self.client, self.cport, self.server, self.sport = net, client, cport, server, sport
        self.cseq = net.rng.randint(1000, 10 ** 6)
        self.sseq = net.rng.randint(10 ** 6, 2 * 10 ** 6)

    def _send(self, from_client: bool, flags: str, data: bytes, ts: float) -> None:
        if from_client:
            self.net.tcp(ts, self.client, self.cport, self.server, self.sport, self.cseq,
                         self.sseq if "A" in flags else 0, flags, data, ttl=128)
            self.cseq += len(data) + (1 if ("S" in flags or "F" in flags) else 0)
        else:
            self.net.tcp(ts, self.server, self.sport, self.client, self.cport, self.sseq,
                         self.cseq if "A" in flags else 0, flags, data, ttl=64)
            self.sseq += len(data) + (1 if ("S" in flags or "F" in flags) else 0)

    def open(self, ts: float) -> "TcpSession":
        self._send(True, "S", b"", ts)
        self._send(False, "SA", b"", ts + 0.0004)
        self._send(True, "A", b"", ts + 0.0008)
        return self

    def refused(self, ts: float) -> None:
        self._send(True, "S", b"", ts)
        self.net.tcp(ts + 0.0004, self.server, self.sport, self.client, self.cport, 0, self.cseq, "RA")

    def c2s(self, data: bytes, ts: float) -> None:
        self._send(True, "PA", data, ts)

    def s2c(self, data: bytes, ts: float) -> None:
        self._send(False, "PA", data, ts)

    def ack_c(self, ts: float) -> None:
        self._send(True, "A", b"", ts)

    def close(self, ts: float) -> None:
        self._send(True, "FA", b"", ts)
        self._send(False, "FA", b"", ts + 0.0004)
        self._send(True, "A", b"", ts + 0.0008)


# ---------------------------------------------------------------- protocol payloads
def modbus_request(tid: int, fc: int, start: int, qty: int, unit: int = 1) -> bytes:
    pdu = struct.pack(">BHH", fc, start, qty)
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def modbus_read_response(tid: int, fc: int, values: List[int], unit: int = 1) -> bytes:
    pdu = struct.pack(">BB", fc, len(values) * 2) + b"".join(struct.pack(">H", v) for v in values)
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def modbus_coils_response(tid: int, qty: int, unit: int = 1) -> bytes:
    nbytes = (qty + 7) // 8
    pdu = struct.pack(">BB", 1, nbytes) + bytes([0x55] * nbytes)
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def modbus_write_single(tid: int, addr: int, value: int, unit: int = 1) -> bytes:
    pdu = struct.pack(">BHH", 6, addr, value)
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def modbus_write_multiple(tid: int, addr: int, values: List[int], unit: int = 1) -> bytes:
    pdu = struct.pack(">BHHB", 16, addr, len(values), len(values) * 2) + b"".join(struct.pack(">H", v) for v in values)
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def modbus_write_multiple_response(tid: int, addr: int, qty: int, unit: int = 1) -> bytes:
    pdu = struct.pack(">BHH", 16, addr, qty)
    return struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def _crc_dnp(data: bytes) -> bytes:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return struct.pack("<H", (~crc) & 0xFFFF)


def dnp3_frame(dest: int, src: int, ctrl: int, user: bytes) -> bytes:
    header = struct.pack("<BBBBHH", 0x05, 0x64, 5 + len(user), ctrl, dest, src)
    out = header + _crc_dnp(header)
    for offset in range(0, len(user), 16):
        block = user[offset:offset + 16]
        out += block + _crc_dnp(block)
    return out


def iec104_i_frame(send_seq: int, recv_seq: int, asdu: bytes) -> bytes:
    return bytes([0x68, 4 + len(asdu)]) + struct.pack("<HH", send_seq << 1, recv_seq << 1) + asdu


def _ber(tag: int, body: bytes) -> bytes:
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    length = len(body).to_bytes((len(body).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + body


def _ber_int(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True)
    return _ber(0x02, raw)


def _ber_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.insert(0, 0x80 | (part & 0x7F))
            part >>= 7
        body += bytes(chunk)
    return _ber(0x06, body)


def snmp_message(community: str, pdu_tag: int, request_id: int, oid: str, value: Optional[int] = None,
                 version: int = 1) -> bytes:
    """SNMP v1 (version=0) / v2c (version=1) message; pdu_tag 0xA0 get, 0xA1 getnext, 0xA2 response, 0xA3 set."""
    val = _ber(0x05, b"") if value is None else _ber_int(value)
    varbind = _ber(0x30, _ber_oid(oid) + val)
    pdu = _ber(pdu_tag, _ber_int(request_id) + _ber_int(0) + _ber_int(0) + _ber(0x30, varbind))
    return _ber(0x30, _ber_int(version) + _ber(0x04, community.encode()) + pdu)


def mqtt_connect(client_id: str, username: Optional[str] = None, password: Optional[str] = None) -> bytes:
    flags = 0x02
    payload = struct.pack(">H", len(client_id)) + client_id.encode()
    if username is not None:
        flags |= 0x80
        payload += struct.pack(">H", len(username)) + username.encode()
    if password is not None:
        flags |= 0x40
        payload += struct.pack(">H", len(password)) + password.encode()
    body = b"\x00\x04MQTT\x04" + bytes([flags]) + b"\x00\x3c" + payload
    return bytes([0x10, len(body)]) + body


def mqtt_publish(topic: str, message: bytes, retain: bool = False) -> bytes:
    body = struct.pack(">H", len(topic)) + topic.encode() + message
    return bytes([0x30 | (0x01 if retain else 0x00), len(body)]) + body


def tls_hello_pair(version: int, offered: List[int], chosen: int) -> Tuple[bytes, bytes]:
    """Minimal TLS ClientHello/ServerHello records (no extensions)."""
    random_bytes = bytes(32)
    suites = b"".join(struct.pack(">H", s) for s in offered)
    ch_body = struct.pack(">H", version) + random_bytes + b"\x00" + struct.pack(">H", len(suites)) + suites + b"\x01\x00"
    ch = b"\x01" + struct.pack(">I", len(ch_body))[1:] + ch_body
    sh_body = struct.pack(">H", version) + random_bytes + b"\x00" + struct.pack(">H", chosen) + b"\x00"
    sh = b"\x02" + struct.pack(">I", len(sh_body))[1:] + sh_body
    record = lambda msg: b"\x16" + struct.pack(">H", version) + struct.pack(">H", len(msg)) + msg  # noqa: E731
    return record(ch), record(sh)


def rtp_packet(seq: int, timestamp: int, payload_type: int = 0, size: int = 160) -> bytes:
    return struct.pack(">BBHII", 0x80, payload_type, seq & 0xFFFF, timestamp & 0xFFFFFFFF, 0x1234ABCD) + b"\xff" * size


def sdp_body(ip: str, media_port: int) -> bytes:
    return (f"v=0\r\no=- 1 1 IN IP4 {ip}\r\ns=-\r\nc=IN IP4 {ip}\r\nt=0 0\r\n"
            f"m=audio {media_port} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n").encode()


WSD_HELLO = (b'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
             b'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
             b'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header>'
             b'<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</wsa:Action></soap:Header>'
             b'<soap:Body><wsd:Hello><wsd:Types>wsdp:Device pub:Computer</wsd:Types></wsd:Hello></soap:Body></soap:Envelope>')
