from __future__ import annotations

import ipaddress
import os
import sqlite3
import struct
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from common import emit

ETH_LEN = 14
ETH_TYPE_IPV4 = 0x0800
ETH_TYPE_IPV6 = 0x86DD
ETH_TYPE_VLAN = 0x8100
ETH_TYPE_QINQ = 0x88A8

ProgressCallback = Callable[[int, int, str], None]


@dataclass
class SessionAccumulator:
    session_id: str
    proto: str
    src_ip: str
    src_port: Optional[int]
    dst_ip: str
    dst_port: Optional[int]
    first_ts_us: int
    last_ts_us: int
    packet_count: int = 0
    byte_count: int = 0


def ingest_pcap_to_sqlite(file_path: str, conn: sqlite3.Connection, on_progress: ProgressCallback) -> int:
    total_size = max(1, os.path.getsize(file_path))
    sessions: Dict[str, SessionAccumulator] = {}
    serials: Dict[str, int] = {}
    pending_rows: List[Tuple[object, ...]] = []
    packet_counter = 0

    def flush_session(session_key: str) -> None:
        session = sessions.pop(session_key, None)
        if not session:
            return
        pending_rows.append(
            (
                session.session_id,
                session.proto,
                session.src_ip,
                session.src_port,
                session.dst_ip,
                session.dst_port,
                session.first_ts_us,
                session.last_ts_us,
                session.packet_count,
                session.byte_count,
            )
        )
        if len(pending_rows) >= 3000:
            write_sessions(conn, pending_rows)
            pending_rows.clear()

    def process_packet(ts_us: int, payload: bytes, packet_len: int) -> None:
        nonlocal packet_counter
        parsed = parse_packet(payload, packet_len)
        if not parsed:
            return

        proto, src_ip, src_port, dst_ip, dst_port, frame_len = parsed
        base_key = f"{proto}|{src_ip}|{src_port}|{dst_ip}|{dst_port}"
        timeout_us = protocol_timeout_us(proto)
        current = sessions.get(base_key)

        if current and ts_us - current.last_ts_us > timeout_us:
            flush_session(base_key)
            current = None

        if not current:
            serial = serials.get(base_key, 0) + 1
            serials[base_key] = serial
            session_id = f"{base_key}|{serial}"
            current = SessionAccumulator(
                session_id=session_id,
                proto=proto,
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                first_ts_us=ts_us,
                last_ts_us=ts_us,
            )
            sessions[base_key] = current

        current.packet_count += 1
        current.byte_count += frame_len
        current.last_ts_us = ts_us
        packet_counter += 1

        if packet_counter % 50_000 == 0:
            stale = [
                key
                for key, session in sessions.items()
                if ts_us - session.last_ts_us > protocol_timeout_us(session.proto)
            ]
            for key in stale:
                flush_session(key)

    with open(file_path, "rb") as handle:
        header = handle.read(24)
        if len(header) < 24:
            raise RuntimeError("Plik PCAP jest uszkodzony lub pusty.")

        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            read_legacy_packets(handle, little_endian=True, nanosecond=(magic == b"\x4d\x3c\xb2\xa1"), on_packet=process_packet, total_size=total_size, on_progress=on_progress)
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            read_legacy_packets(handle, little_endian=False, nanosecond=(magic == b"\xa1\xb2\x3c\x4d"), on_packet=process_packet, total_size=total_size, on_progress=on_progress)
        elif magic in (b"\x0a\x0d\x0d\x0a", b"\x0d\x0a\x0a\x0d"):
            handle.seek(0)
            read_pcapng_packets(handle, on_packet=process_packet, total_size=total_size, on_progress=on_progress)
        else:
            raise RuntimeError("Nieznany format pliku (oczekiwano pcap/pcapng).")

    for key in list(sessions.keys()):
        flush_session(key)

    if pending_rows:
        write_sessions(conn, pending_rows)
        pending_rows.clear()

    conn.commit()
    return packet_counter


def write_sessions(conn: sqlite3.Connection, rows: List[Tuple[object, ...]]) -> None:
    conn.executemany(
        """
        INSERT INTO pcap_sessions (
          session_id, proto, src_ip, src_port, dst_ip, dst_port,
          first_ts_us, last_ts_us, packet_count, byte_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )


def read_legacy_packets(
    handle,
    little_endian: bool,
    nanosecond: bool,
    on_packet: Callable[[int, bytes, int], None],
    total_size: int,
    on_progress: ProgressCallback,
) -> None:
    order = "<" if little_endian else ">"
    packet_index = 0
    while True:
        packet_header = handle.read(16)
        if len(packet_header) < 16:
            break
        ts_sec, ts_frac, captured_len, original_len = struct.unpack(order + "IIII", packet_header)
        payload = handle.read(captured_len)
        if len(payload) < captured_len:
            break
        ts_us = ts_sec * 1_000_000 + (ts_frac // 1000 if nanosecond else ts_frac)
        on_packet(ts_us, payload, original_len)
        packet_index += 1
        if packet_index % 25_000 == 0:
            on_progress(handle.tell(), total_size, f"Parsowanie PCAP: {packet_index:,} pakietow")


def read_pcapng_packets(handle, on_packet: Callable[[int, bytes, int], None], total_size: int, on_progress: ProgressCallback) -> None:
    endian = "<"
    interface_resolutions: Dict[int, float] = {}
    interface_index = 0
    packet_index = 0

    while True:
        header = handle.read(8)
        if len(header) < 8:
            break

        block_type_le, block_len_le = struct.unpack("<II", header)
        block_type = block_type_le
        block_len = block_len_le
        if block_len < 12:
            break

        rest = handle.read(block_len - 8)
        if len(rest) < block_len - 8:
            break

        body = rest[:-4]

        if block_type == 0x0A0D0D0A and len(body) >= 4:
            if body[:4] == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif body[:4] == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            continue

        if block_type == 0x00000001:
            resolution = parse_idb_resolution(body, endian)
            interface_resolutions[interface_index] = resolution
            interface_index += 1
            continue

        if block_type != 0x00000006 or len(body) < 20:
            continue

        interface_id, ts_high, ts_low, captured_len, original_len = struct.unpack(endian + "IIIII", body[:20])
        packet_data = body[20 : 20 + captured_len]
        if len(packet_data) < captured_len:
            continue

        resolution = interface_resolutions.get(interface_id, 1e-6)
        raw_ts = (ts_high << 32) | ts_low
        ts_us = int(raw_ts * (resolution * 1_000_000))
        on_packet(ts_us, packet_data, original_len)
        packet_index += 1

        if packet_index % 25_000 == 0:
            on_progress(handle.tell(), total_size, f"Parsowanie PCAPNG: {packet_index:,} pakietow")


def parse_idb_resolution(body: bytes, endian: str) -> float:
    if len(body) < 8:
        return 1e-6
    options = body[8:]
    idx = 0
    while idx + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[idx : idx + 4])
        idx += 4
        if code == 0:
            break
        value = options[idx : idx + length]
        idx += length + ((4 - (length % 4)) % 4)
        if code == 9 and len(value) >= 1:
            ts_resol = value[0]
            if ts_resol & 0x80:
                exp = ts_resol & 0x7F
                return float(2 ** (-exp))
            return float(10 ** (-ts_resol))
    return 1e-6


def parse_packet(payload: bytes, original_len: int) -> Optional[Tuple[str, str, Optional[int], str, Optional[int], int]]:
    if len(payload) < ETH_LEN:
        return None

    eth_type = int.from_bytes(payload[12:14], "big")
    offset = ETH_LEN

    if eth_type in (ETH_TYPE_VLAN, ETH_TYPE_QINQ) and len(payload) >= offset + 4:
        eth_type = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        offset += 4

    if eth_type == ETH_TYPE_IPV4:
        return parse_ipv4_packet(payload[offset:], original_len)
    if eth_type == ETH_TYPE_IPV6:
        return parse_ipv6_packet(payload[offset:], original_len)

    return None


def parse_ipv4_packet(payload: bytes, original_len: int) -> Optional[Tuple[str, str, Optional[int], str, Optional[int], int]]:
    if len(payload) < 20:
        return None
    version = payload[0] >> 4
    ihl = (payload[0] & 0x0F) * 4
    if version != 4 or len(payload) < ihl:
        return None

    protocol_num = payload[9]
    src_ip = ".".join(str(byte) for byte in payload[12:16])
    dst_ip = ".".join(str(byte) for byte in payload[16:20])
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    if len(payload) >= ihl + 4 and protocol_num in (6, 17):
        src_port = int.from_bytes(payload[ihl : ihl + 2], "big")
        dst_port = int.from_bytes(payload[ihl + 2 : ihl + 4], "big")

    proto = protocol_name(protocol_num)
    return proto, src_ip, src_port, dst_ip, dst_port, original_len


def parse_ipv6_packet(payload: bytes, original_len: int) -> Optional[Tuple[str, str, Optional[int], str, Optional[int], int]]:
    if len(payload) < 40:
        return None
    version = payload[0] >> 4
    if version != 6:
        return None
    next_header = payload[6]

    src_ip = str(ipaddress.IPv6Address(payload[8:24]))
    dst_ip = str(ipaddress.IPv6Address(payload[24:40]))
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    if len(payload) >= 44 and next_header in (6, 17):
        src_port = int.from_bytes(payload[40:42], "big")
        dst_port = int.from_bytes(payload[42:44], "big")

    proto = protocol_name(next_header)
    return proto, src_ip, src_port, dst_ip, dst_port, original_len


def protocol_name(code: int) -> str:
    if code == 6:
        return "TCP"
    if code == 17:
        return "UDP"
    if code == 1:
        return "ICMP"
    if code == 58:
        return "ICMPv6"
    return f"IP-{code}"


def protocol_timeout_us(proto: str) -> int:
    if proto == "TCP":
        return 30_000_000
    if proto == "UDP":
        return 15_000_000
    return 10_000_000
