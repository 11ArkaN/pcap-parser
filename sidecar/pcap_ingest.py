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
    dns_records: Dict[Tuple[str, str], List[int]] = {}
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
        for hostname, resolved_ip in extract_dns_answers_from_frame(payload):
            key = (hostname, resolved_ip)
            state = dns_records.get(key)
            if state is None:
                dns_records[key] = [ts_us, ts_us, 1]
            else:
                if ts_us < state[0]:
                    state[0] = ts_us
                if ts_us > state[1]:
                    state[1] = ts_us
                state[2] += 1

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

    if dns_records:
        write_dns_answers(conn, dns_records)

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


def write_dns_answers(conn: sqlite3.Connection, dns_records: Dict[Tuple[str, str], List[int]]) -> None:
    rows: List[Tuple[object, ...]] = []
    for (hostname, resolved_ip), state in dns_records.items():
        rows.append((hostname, resolved_ip, int(state[0]), int(state[1]), int(state[2])))
    if not rows:
        return
    conn.executemany(
        """
        INSERT INTO pcap_dns_answers (
          hostname, resolved_ip, first_seen_us, last_seen_us, hit_count
        ) VALUES (?, ?, ?, ?, ?)
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


def extract_dns_answers_from_frame(frame: bytes) -> List[Tuple[str, str]]:
    if len(frame) < ETH_LEN:
        return []

    eth_type = int.from_bytes(frame[12:14], "big")
    offset = ETH_LEN
    if eth_type in (ETH_TYPE_VLAN, ETH_TYPE_QINQ) and len(frame) >= offset + 4:
        eth_type = int.from_bytes(frame[offset + 2 : offset + 4], "big")
        offset += 4

    if eth_type == ETH_TYPE_IPV4:
        return extract_dns_answers_from_ipv4(frame[offset:])
    if eth_type == ETH_TYPE_IPV6:
        return extract_dns_answers_from_ipv6(frame[offset:])
    return []


def extract_dns_answers_from_ipv4(payload: bytes) -> List[Tuple[str, str]]:
    if len(payload) < 20:
        return []
    version = payload[0] >> 4
    ihl = (payload[0] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(payload) < ihl + 8:
        return []
    proto = payload[9]
    if proto != 17:
        return []
    src_port = int.from_bytes(payload[ihl : ihl + 2], "big")
    dst_port = int.from_bytes(payload[ihl + 2 : ihl + 4], "big")
    if not is_dns_port(src_port) and not is_dns_port(dst_port):
        return []
    udp_len = int.from_bytes(payload[ihl + 4 : ihl + 6], "big")
    if udp_len < 8:
        return []
    udp_payload_start = ihl + 8
    udp_payload_end = min(len(payload), ihl + udp_len)
    if udp_payload_end <= udp_payload_start:
        return []
    return parse_dns_response_payload(payload[udp_payload_start:udp_payload_end])


def extract_dns_answers_from_ipv6(payload: bytes) -> List[Tuple[str, str]]:
    if len(payload) < 48:
        return []
    version = payload[0] >> 4
    if version != 6:
        return []
    next_header = payload[6]
    if next_header != 17:
        return []
    udp_offset = 40
    src_port = int.from_bytes(payload[udp_offset : udp_offset + 2], "big")
    dst_port = int.from_bytes(payload[udp_offset + 2 : udp_offset + 4], "big")
    if not is_dns_port(src_port) and not is_dns_port(dst_port):
        return []
    udp_len = int.from_bytes(payload[udp_offset + 4 : udp_offset + 6], "big")
    if udp_len < 8:
        return []
    udp_payload_start = udp_offset + 8
    udp_payload_end = min(len(payload), udp_offset + udp_len)
    if udp_payload_end <= udp_payload_start:
        return []
    return parse_dns_response_payload(payload[udp_payload_start:udp_payload_end])


def is_dns_port(port: int) -> bool:
    return port in (53, 5353)


def parse_dns_response_payload(payload: bytes) -> List[Tuple[str, str]]:
    if len(payload) < 12:
        return []

    flags = int.from_bytes(payload[2:4], "big")
    is_response = bool(flags & 0x8000)
    if not is_response:
        return []

    qdcount = int.from_bytes(payload[4:6], "big")
    ancount = int.from_bytes(payload[6:8], "big")
    if ancount <= 0:
        return []

    offset = 12
    questions: List[str] = []
    for _ in range(qdcount):
        qname, offset = decode_dns_name(payload, offset)
        if offset is None:
            return []
        if offset + 4 > len(payload):
            return []
        offset += 4
        if qname:
            questions.append(qname)

    cname_map: Dict[str, str] = {}
    answer_pairs: List[Tuple[str, str]] = []
    for _ in range(ancount):
        rr_name, next_offset = decode_dns_name(payload, offset)
        if next_offset is None:
            return answer_pairs
        offset = next_offset
        if offset + 10 > len(payload):
            return answer_pairs
        rr_type = int.from_bytes(payload[offset : offset + 2], "big")
        rr_class = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        rdlength = int.from_bytes(payload[offset + 8 : offset + 10], "big")
        rdata_offset = offset + 10
        rdata_end = rdata_offset + rdlength
        if rdata_end > len(payload):
            return answer_pairs

        if rr_class == 1:
            if rr_type == 1 and rdlength == 4:
                target_ip = ".".join(str(part) for part in payload[rdata_offset:rdata_end])
                append_dns_pair(answer_pairs, rr_name, target_ip)
            elif rr_type == 28 and rdlength == 16:
                target_ip = str(ipaddress.IPv6Address(payload[rdata_offset:rdata_end]))
                append_dns_pair(answer_pairs, rr_name, target_ip)
            elif rr_type == 5:
                cname_target, _ = decode_dns_name(payload, rdata_offset)
                if rr_name and cname_target:
                    cname_map[rr_name] = cname_target
        offset = rdata_end

    if cname_map and answer_pairs:
        by_host: Dict[str, List[str]] = {}
        for host, target_ip in answer_pairs:
            by_host.setdefault(host, []).append(target_ip)
        propagated: List[Tuple[str, str]] = []
        for alias, canonical in cname_map.items():
            ips = by_host.get(canonical, [])
            for target_ip in ips:
                propagated.append((alias, target_ip))
        answer_pairs.extend(propagated)

    if questions and answer_pairs:
        question_seed = questions[0]
        seeded: List[Tuple[str, str]] = []
        for _host, target_ip in answer_pairs:
            seeded.append((question_seed, target_ip))
        answer_pairs.extend(seeded)

    deduped: List[Tuple[str, str]] = []
    seen = set()
    for host, target_ip in answer_pairs:
        normalized_host = normalize_hostname(host)
        if not normalized_host:
            continue
        key = (normalized_host, target_ip)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(key)
    return deduped


def append_dns_pair(pairs: List[Tuple[str, str]], host: Optional[str], target_ip: str) -> None:
    if not host:
        return
    normalized_ip = normalize_ip_literal(target_ip)
    if not normalized_ip:
        return
    pairs.append((host, normalized_ip))


def decode_dns_name(payload: bytes, offset: int, depth: int = 0) -> Tuple[Optional[str], Optional[int]]:
    if offset >= len(payload):
        return None, None
    if depth > 24:
        return None, None

    labels: List[str] = []
    current = offset
    jumped = False
    after_jump_offset: Optional[int] = None

    while True:
        if current >= len(payload):
            return None, None
        length = payload[current]
        if length == 0:
            current += 1
            break
        if (length & 0xC0) == 0xC0:
            if current + 1 >= len(payload):
                return None, None
            pointer = ((length & 0x3F) << 8) | payload[current + 1]
            if not jumped:
                after_jump_offset = current + 2
                jumped = True
            label, _ = decode_dns_name(payload, pointer, depth + 1)
            if label:
                labels.append(label)
            current += 2
            break
        current += 1
        if current + length > len(payload):
            return None, None
        try:
            labels.append(payload[current : current + length].decode("utf-8", errors="ignore"))
        except Exception:
            return None, None
        current += length

    hostname = normalize_hostname(".".join(part for part in labels if part))
    return hostname, (after_jump_offset if jumped and after_jump_offset is not None else current)


def normalize_hostname(hostname: str) -> Optional[str]:
    text = (hostname or "").strip().strip(".").lower()
    if not text:
        return None
    return text


def normalize_ip_literal(value: str) -> Optional[str]:
    text = (value or "").strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None
