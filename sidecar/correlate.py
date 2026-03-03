from __future__ import annotations

import json
import math
import re
import sqlite3
import statistics
from collections import deque
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple

from common import is_private_ip

ProgressCallback = Callable[[int, int, str], None]


@dataclass
class SessionRecord:
    session_id: str
    proto: str
    src_ip: str
    src_port: Optional[int]
    dst_ip: str
    dst_port: Optional[int]
    first_ts_us: int
    last_ts_us: int
    packet_count: int
    byte_count: int

    @property
    def center_ts_us(self) -> int:
        return (self.first_ts_us + self.last_ts_us) // 2


@dataclass
class ProcmonEvent:
    event_id: str
    ts_us: int
    pid: Optional[int]
    tid: Optional[int]
    process_name: Optional[str]
    process_path: Optional[str]
    command_line: Optional[str]
    user_name: Optional[str]
    company: Optional[str]
    parent_pid: Optional[int]
    integrity_level: Optional[str]
    signer: Optional[str]
    image_hash: Optional[str]
    operation: Optional[str]
    result: Optional[str]
    path: Optional[str]
    detail: Optional[str]
    proto: str
    local_ip: Optional[str]
    local_port: Optional[int]
    remote_ip: Optional[str]
    remote_port: Optional[int]
    direction: str


@dataclass
class CandidateEdge:
    session_idx: int
    event_idx: int
    score: int
    offset_us: int
    reasons: List[Dict[str, object]]


@dataclass
class Edge:
    to: int
    rev: int
    cap: int
    cost: int


@dataclass
class SessionShape:
    local_ip: Optional[str]
    local_port: Optional[int]
    remote_ip: Optional[str]
    remote_port: Optional[int]
    direction: str


def correlate_to_report(
    conn: sqlite3.Connection,
    analysis_id: str,
    pcap_file_path: str,
    procmon_files: Sequence[str],
    parser_mode: str,
    warnings: List[str],
    options: Dict[str, object],
    on_progress: ProgressCallback,
) -> Dict[str, object]:
    sessions = load_sessions(conn)
    total_sessions = len(sessions)
    total_procmon_events = count_procmon_events(conn)
    procmon_time_bounds = get_procmon_time_bounds(conn)
    dns_hosts_by_ip, dns_ips_by_host = load_dns_maps(conn)

    if total_sessions == 0:
        raise RuntimeError("Brak sesji PCAP do korelacji.")

    if total_procmon_events == 0:
        raise RuntimeError("Brak eventow sieciowych Procmon do korelacji.")

    on_progress(0, max(1, total_sessions), "Szacowanie synchronizacji czasu PCAP <-> Procmon")
    time_offset_us = estimate_time_offset(conn, sessions)
    time_offset_us = calibrate_time_offset_from_absolute_ranges(
        sessions=sessions,
        procmon_time_bounds=procmon_time_bounds,
        estimated_offset_us=time_offset_us,
        warnings=warnings,
    )
    drift = 1.0

    on_progress(0, max(1, total_sessions), "Budowanie kandydatow dopasowania")
    time_window_ms = int(options.get("timeWindowMs", 2000) or 2000)
    min_score = int(options.get("minScore", 50) or 50)
    max_candidates = int(options.get("maxCandidatesPerSession", 8) or 8)
    base_time_window_us = max(100_000, time_window_ms * 1000)
    edges, event_by_index = build_candidates(
        conn=conn,
        sessions=sessions,
        time_offset_us=time_offset_us,
        time_window_us=base_time_window_us,
        min_score=min_score,
        max_candidates=max_candidates,
        dns_hosts_by_ip=dns_hosts_by_ip,
        dns_ips_by_host=dns_ips_by_host,
        on_progress=on_progress,
    )

    minimum_expected_edges = max(10, int(total_sessions * 0.05))
    if len(edges) < minimum_expected_edges:
        on_progress(0, max(1, total_sessions), "Rozszerzanie okna czasu dla korelacji")
        candidate_configs = [
            (base_time_window_us * 10, max(min_score - 5, 40)),
            (base_time_window_us * 30, max(min_score - 10, 35)),
        ]
        best_edges = edges
        best_event_by_index = event_by_index
        for expanded_window, expanded_score in candidate_configs:
            alt_edges, alt_event_by_index = build_candidates(
                conn=conn,
                sessions=sessions,
                time_offset_us=time_offset_us,
                time_window_us=expanded_window,
                min_score=expanded_score,
                max_candidates=max_candidates,
                dns_hosts_by_ip=dns_hosts_by_ip,
                dns_ips_by_host=dns_ips_by_host,
                on_progress=on_progress,
            )
            if len(alt_edges) > len(best_edges):
                best_edges = alt_edges
                best_event_by_index = alt_event_by_index
        if len(best_edges) > len(edges):
            warnings.append(
                f"Automatycznie rozszerzono okno czasu (offset={time_offset_us} us), bo podstawowe dopasowanie bylo zbyt male ({len(edges)} krawedzi)."
            )
            edges = best_edges
            event_by_index = best_event_by_index

    selected_edges: List[CandidateEdge] = []
    if not edges:
        warnings.append("Nie znaleziono kandydatow dopasowania przy obecnych progach.")
    else:
        on_progress(0, max(1, len(edges)), "Globalny matching (max-weight)")
        selected_edges = max_weight_matching(
            total_sessions=total_sessions,
            event_by_index=event_by_index,
            candidate_edges=edges,
            on_progress=on_progress,
            event_capacity=32,
            progress_label="Matching",
        )

    unmatched_session_indices = sorted(set(range(total_sessions)) - {edge.session_idx for edge in selected_edges})
    if unmatched_session_indices:
        fallback_window_us = max(base_time_window_us * 25, 180_000_000)
        fallback_min_score = max(min_score - 15, 32)
        on_progress(0, max(1, len(unmatched_session_indices)), "Fallback IP-first dla niedopasowanych sesji")
        fallback_edges = build_ip_first_fallback_candidates(
            conn=conn,
            sessions=sessions,
            unmatched_session_indices=unmatched_session_indices,
            time_offset_us=time_offset_us,
            time_window_us=fallback_window_us,
            min_score=fallback_min_score,
            max_candidates=max(max_candidates * 2, 10),
            event_by_index=event_by_index,
            procmon_time_bounds=procmon_time_bounds,
            dns_hosts_by_ip=dns_hosts_by_ip,
            dns_ips_by_host=dns_ips_by_host,
            on_progress=on_progress,
        )
        if fallback_edges:
            event_capacity = 64
            used_event_capacity: Dict[int, int] = {}
            for edge in selected_edges:
                used_event_capacity[edge.event_idx] = used_event_capacity.get(edge.event_idx, 0) + 1
            event_remaining_capacity: Dict[int, int] = {
                event_idx: max(0, event_capacity - used_event_capacity.get(event_idx, 0))
                for event_idx in range(len(event_by_index))
            }
            fallback_selected = max_weight_matching(
                total_sessions=total_sessions,
                event_by_index=event_by_index,
                candidate_edges=fallback_edges,
                on_progress=on_progress,
                event_capacity=event_capacity,
                session_indices=unmatched_session_indices,
                event_capacity_by_index=event_remaining_capacity,
                progress_label="Fallback matching",
            )
            if fallback_selected:
                selected_edges.extend(fallback_selected)
                warnings.append(
                    f"Fallback IP-first dopasowal dodatkowo {len(fallback_selected)} sesji "
                    f"(okno={fallback_window_us // 1000} ms, prog={fallback_min_score})."
                )
            else:
                warnings.append("Fallback IP-first nie znalazl dodatkowych dopasowan.")
        else:
            warnings.append("Fallback IP-first nie wygenerowal kandydatow.")

    return build_report(
        analysis_id=analysis_id,
        pcap_file_path=pcap_file_path,
        procmon_files=procmon_files,
        parser_mode=parser_mode,
        warnings=warnings,
        time_offset_us=time_offset_us,
        drift=drift,
        sessions=sessions,
        event_by_index=event_by_index,
        selected_edges=selected_edges,
        total_procmon_events=total_procmon_events,
    )


def load_sessions(conn: sqlite3.Connection) -> List[SessionRecord]:
    cursor = conn.execute(
        """
        SELECT session_id, proto, src_ip, src_port, dst_ip, dst_port, first_ts_us, last_ts_us, packet_count, byte_count
        FROM pcap_sessions
        ORDER BY first_ts_us ASC
        """
    )
    rows = cursor.fetchall()
    sessions: List[SessionRecord] = []
    for row in rows:
        sessions.append(
            SessionRecord(
                session_id=row[0],
                proto=row[1],
                src_ip=row[2],
                src_port=row[3],
                dst_ip=row[4],
                dst_port=row[5],
                first_ts_us=row[6],
                last_ts_us=row[7],
                packet_count=row[8],
                byte_count=row[9],
            )
        )
    return sessions


def count_procmon_events(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) FROM procmon_events").fetchone()
    return int(row[0]) if row else 0


def load_dns_maps(conn: sqlite3.Connection) -> Tuple[Dict[str, List[str]], Dict[str, Set[str]]]:
    has_table_row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pcap_dns_answers' LIMIT 1"
    ).fetchone()
    if not has_table_row:
        return {}, {}

    rows = conn.execute(
        """
        SELECT hostname, resolved_ip, hit_count
        FROM pcap_dns_answers
        ORDER BY hit_count DESC
        """
    ).fetchall()
    hosts_by_ip: Dict[str, List[str]] = {}
    ips_by_host: Dict[str, Set[str]] = {}
    for row in rows:
        hostname = normalize_hostname(str(row[0] or ""))
        resolved_ip = str(row[1] or "").strip()
        if not hostname or not resolved_ip:
            continue
        ips_by_host.setdefault(hostname, set()).add(resolved_ip)
        host_list = hosts_by_ip.setdefault(resolved_ip, [])
        if hostname not in host_list:
            host_list.append(hostname)

    for ip, hostnames in list(hosts_by_ip.items()):
        hosts_by_ip[ip] = hostnames[:12]
    return hosts_by_ip, ips_by_host


def get_procmon_time_bounds(conn: sqlite3.Connection) -> Optional[Tuple[int, int]]:
    row = conn.execute("SELECT MIN(ts_us), MAX(ts_us) FROM procmon_events").fetchone()
    if not row or row[0] is None or row[1] is None:
        return None
    return int(row[0]), int(row[1])


def calibrate_time_offset_from_absolute_ranges(
    sessions: List[SessionRecord],
    procmon_time_bounds: Optional[Tuple[int, int]],
    estimated_offset_us: int,
    warnings: List[str],
) -> int:
    if not sessions or not procmon_time_bounds:
        return estimated_offset_us

    pcap_min = min(session.first_ts_us for session in sessions)
    pcap_max = max(session.last_ts_us for session in sessions)
    pcap_range = max(1, pcap_max - pcap_min)
    procmon_min, procmon_max = procmon_time_bounds

    def overlap_ratio(candidate_offset_us: int) -> float:
        shifted_min = pcap_min + candidate_offset_us
        shifted_max = pcap_max + candidate_offset_us
        overlap = max(0, min(shifted_max, procmon_max) - max(shifted_min, procmon_min))
        return float(overlap) / float(pcap_range)

    current_overlap = overlap_ratio(estimated_offset_us)
    if current_overlap >= 0.10:
        return estimated_offset_us

    pcap_center = (pcap_min + pcap_max) // 2
    procmon_center = (procmon_min + procmon_max) // 2
    center_offset_us = procmon_center - pcap_center
    center_overlap = overlap_ratio(center_offset_us)
    if center_overlap > current_overlap + 0.10:
        warnings.append(
            "Skorygowano offset czasu na podstawie absolutnych zakresow znacznikow czasu "
            f"(old={estimated_offset_us} us, new={center_offset_us} us, overlap={center_overlap:.2f})."
        )
        return center_offset_us

    return estimated_offset_us


def estimate_time_offset(conn: sqlite3.Connection, sessions: List[SessionRecord]) -> int:
    diffs: List[int] = []
    sample_limit = min(len(sessions), 1500)
    for session in sessions[:sample_limit]:
        shape = infer_session_shape(session)
        row = query_nearest_event_for_offset(conn, session, shape)
        if row:
            diffs.append(int(row[0]) - session.center_ts_us)
    if not diffs:
        return 0
    if len(diffs) > 50:
        median = statistics.median(diffs)
        mad = statistics.median([abs(item - median) for item in diffs]) or 1
        filtered = [item for item in diffs if abs(item - median) <= 3 * mad]
        if filtered:
            diffs = filtered
    return int(statistics.median(diffs))


def query_nearest_event_for_offset(
    conn: sqlite3.Connection,
    session: SessionRecord,
    shape: SessionShape,
) -> Optional[Tuple[int]]:
    if shape.local_port is not None:
        row = conn.execute(
            """
        SELECT ts_us
        FROM procmon_events
        WHERE proto = ?
          AND local_port = ?
        ORDER BY ABS(ts_us - ?)
        LIMIT 1
    """,
            (session.proto, shape.local_port, session.center_ts_us),
        ).fetchone()
        if row:
            return row

    if shape.remote_ip and shape.remote_port is not None:
        row = conn.execute(
            """
        SELECT ts_us
        FROM procmon_events
        WHERE proto = ?
          AND remote_ip = ?
          AND remote_port = ?
        ORDER BY ABS(ts_us - ?)
        LIMIT 1
    """,
            (session.proto, shape.remote_ip, shape.remote_port, session.center_ts_us),
        ).fetchone()
        if row:
            return row

    return None


def build_candidates(
    conn: sqlite3.Connection,
    sessions: List[SessionRecord],
    time_offset_us: int,
    time_window_us: int,
    min_score: int,
    max_candidates: int,
    dns_hosts_by_ip: Dict[str, List[str]],
    dns_ips_by_host: Dict[str, Set[str]],
    on_progress: ProgressCallback,
) -> Tuple[List[CandidateEdge], List[ProcmonEvent]]:
    edges: List[CandidateEdge] = []
    event_index_by_id: Dict[str, int] = {}
    event_by_index: List[ProcmonEvent] = []
    total = len(sessions)

    for idx, session in enumerate(sessions):
        lower_bound = session.first_ts_us + time_offset_us - time_window_us
        upper_bound = session.last_ts_us + time_offset_us + time_window_us
        shape = infer_session_shape(session)
        endpoint_pairs_all = endpoint_pairs(session)
        if not endpoint_pairs_all and shape.local_port is None:
            continue

        remote_pairs: List[Tuple[str, int]] = []
        if shape.remote_ip and shape.remote_port is not None:
            remote_pairs.append((shape.remote_ip, shape.remote_port))

        local_ports = [shape.local_port] if shape.local_port is not None else []
        ip_candidates = [ip for ip, _port in endpoint_pairs_all if ip]
        hostname_candidates = hostname_alias_candidates_for_ips(ip_candidates, dns_hosts_by_ip)

        event_rows = query_events_for_session(
            conn=conn,
            proto=session.proto,
            remote_pairs=remote_pairs or endpoint_pairs_all,
            local_ports=local_ports,
            ip_candidates=ip_candidates,
            hostname_candidates=hostname_candidates,
            lower_bound=lower_bound,
            upper_bound=upper_bound,
            limit=max(max_candidates * 64, 256),
        )
        scored: List[Tuple[int, Dict[str, object], ProcmonEvent]] = []
        for event in event_rows:
            score, offset_us, reasons = score_session_event(
                session=session,
                event=event,
                time_offset_us=time_offset_us,
                time_window_us=time_window_us,
                dns_ips_by_host=dns_ips_by_host,
            )
            if score < min_score:
                continue
            scored.append((score, {"offset_us": offset_us, "reasons": reasons}, event))

        scored.sort(key=lambda item: item[0], reverse=True)
        for score, metadata, event in scored[:max_candidates]:
            event_idx = event_index_by_id.get(event.event_id)
            if event_idx is None:
                event_idx = len(event_by_index)
                event_index_by_id[event.event_id] = event_idx
                event_by_index.append(event)
            edges.append(
                CandidateEdge(
                    session_idx=idx,
                    event_idx=event_idx,
                    score=score,
                    offset_us=int(metadata["offset_us"]),
                    reasons=metadata["reasons"],  # type: ignore[arg-type]
                )
            )

        if (idx + 1) % 200 == 0 or idx + 1 == total:
            on_progress(idx + 1, total, f"Kandydaci: {idx + 1:,}/{total:,} sesji")

    return edges, event_by_index


def build_ip_first_fallback_candidates(
    conn: sqlite3.Connection,
    sessions: List[SessionRecord],
    unmatched_session_indices: List[int],
    time_offset_us: int,
    time_window_us: int,
    min_score: int,
    max_candidates: int,
    event_by_index: List[ProcmonEvent],
    procmon_time_bounds: Optional[Tuple[int, int]],
    dns_hosts_by_ip: Dict[str, List[str]],
    dns_ips_by_host: Dict[str, Set[str]],
    on_progress: ProgressCallback,
) -> List[CandidateEdge]:
    edges: List[CandidateEdge] = []
    event_index_by_id: Dict[str, int] = {event.event_id: idx for idx, event in enumerate(event_by_index)}
    total = len(unmatched_session_indices)

    for position, session_idx in enumerate(unmatched_session_indices, start=1):
        session = sessions[session_idx]
        lower_bound = session.first_ts_us + time_offset_us - time_window_us
        upper_bound = session.last_ts_us + time_offset_us + time_window_us
        ip_candidates = fallback_ip_candidates_for_session(session)
        if not ip_candidates:
            continue
        hostname_candidates = hostname_alias_candidates_for_ips(ip_candidates, dns_hosts_by_ip)

        events = query_events_for_session_ip_first(
            conn=conn,
            ip_candidates=ip_candidates,
            hostname_candidates=hostname_candidates,
            lower_bound=lower_bound,
            upper_bound=upper_bound,
            center_ts_us=session.center_ts_us + time_offset_us,
            limit=max(max_candidates * 120, 400),
        )
        if not events and procmon_time_bounds:
            procmon_min_ts, procmon_max_ts = procmon_time_bounds
            events = query_events_for_session_ip_first(
                conn=conn,
                ip_candidates=ip_candidates,
                hostname_candidates=hostname_candidates,
                lower_bound=procmon_min_ts,
                upper_bound=procmon_max_ts,
                center_ts_us=session.center_ts_us + time_offset_us,
                limit=max(max_candidates * 200, 600),
            )
        scored: List[Tuple[int, Dict[str, object], ProcmonEvent]] = []
        for event in events:
            score, offset_us, reasons = score_session_event(
                session=session,
                event=event,
                time_offset_us=time_offset_us,
                time_window_us=time_window_us,
                dns_ips_by_host=dns_ips_by_host,
            )
            score, reasons = tune_ip_first_score(session, event, score, reasons)
            if score < min_score:
                continue
            scored.append((score, {"offset_us": offset_us, "reasons": reasons}, event))

        scored.sort(key=lambda item: item[0], reverse=True)
        for score, metadata, event in scored[:max_candidates]:
            event_idx = event_index_by_id.get(event.event_id)
            if event_idx is None:
                event_idx = len(event_by_index)
                event_index_by_id[event.event_id] = event_idx
                event_by_index.append(event)
            reasons = list(metadata["reasons"])  # type: ignore[arg-type]
            reasons.append(
                {
                    "code": "fallback_ip_first",
                    "score": 0,
                    "detail": "Dopasowanie z etapu fallback IP-first (poluzowane kryteria).",
                }
            )
            edges.append(
                CandidateEdge(
                    session_idx=session_idx,
                    event_idx=event_idx,
                    score=score,
                    offset_us=int(metadata["offset_us"]),
                    reasons=reasons,  # type: ignore[arg-type]
                )
            )

        if position % 150 == 0 or position == total:
            on_progress(position, total, f"Fallback IP-first: {position:,}/{total:,} sesji")

    return edges


def fallback_ip_candidates_for_session(session: SessionRecord) -> List[str]:
    ordered = [session.src_ip, session.dst_ip]
    public = [ip for ip in ordered if ip and not is_private_ip(ip)]
    private = [ip for ip in ordered if ip and is_private_ip(ip)]
    # Public IP first, but keep private as fallback anchors (LAN traffic/NAT visibility).
    return dedupe_preserve_order(public + private)


def dedupe_preserve_order(items: List[str]) -> List[str]:
    seen: Set[str] = set()
    result: List[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def hostname_alias_candidates_for_ips(ip_candidates: List[str], dns_hosts_by_ip: Dict[str, List[str]]) -> List[str]:
    aliases: List[str] = []
    for ip in ip_candidates:
        for hostname in dns_hosts_by_ip.get(ip, []):
            aliases.append(hostname)
    return dedupe_preserve_order(aliases)[:20]


def tune_ip_first_score(
    session: SessionRecord,
    event: ProcmonEvent,
    base_score: int,
    reasons: List[Dict[str, object]],
) -> Tuple[int, List[Dict[str, object]]]:
    score = base_score
    tuned_reasons = list(reasons)

    shape = infer_session_shape(session)
    if event.proto == session.proto:
        score += 6
        tuned_reasons.append({"code": "proto_exact", "score": 6, "detail": "Zgodnosc protokolu TCP/UDP."})
    else:
        score -= 4
        tuned_reasons.append({"code": "proto_mismatch", "score": -4, "detail": "Rozny protokol - obnizenie pewnosci."})

    if shape.remote_ip and (event.remote_ip == shape.remote_ip or event.local_ip == shape.remote_ip):
        score += 8
        tuned_reasons.append({"code": "remote_ip_anchor", "score": 8, "detail": "Kotwica IP z PCAP obecna w evencie Procmon."})

    return max(0, min(100, score)), tuned_reasons


def query_events_for_session(
    conn: sqlite3.Connection,
    proto: str,
    remote_pairs: List[Tuple[str, int]],
    local_ports: List[int],
    ip_candidates: List[str],
    hostname_candidates: List[str],
    lower_bound: int,
    upper_bound: int,
    limit: int,
) -> List[ProcmonEvent]:
    clauses: List[str] = []
    params: List[object] = [proto, lower_bound, upper_bound]
    for ip, port in remote_pairs:
        clauses.append("(remote_ip = ? AND remote_port = ?)")
        params.extend([ip, port])
    if local_ports:
        placeholders = ", ".join("?" for _ in local_ports)
        clauses.append(f"(local_port IN ({placeholders}))")
        params.extend(local_ports)
    if ip_candidates:
        placeholders = ", ".join("?" for _ in ip_candidates)
        clauses.append(f"(remote_ip IN ({placeholders}))")
        params.extend(ip_candidates)
    if hostname_candidates:
        placeholders = ", ".join("?" for _ in hostname_candidates)
        clauses.append(f"(remote_ip IN ({placeholders}))")
        params.extend(hostname_candidates)

    endpoint_sql = " OR ".join(clauses) if clauses else "1=1"
    query = f"""
        SELECT event_id, ts_us, pid, tid, process_name, process_path, command_line, user_name, company, parent_pid,
               integrity_level, signer, image_hash, operation, result, path, detail, proto, local_ip, local_port, remote_ip, remote_port, direction
        FROM procmon_events
        WHERE proto = ?
          AND ts_us BETWEEN ? AND ?
          AND ({endpoint_sql})
        ORDER BY ts_us ASC
        LIMIT ?
    """
    params.append(limit)
    cursor = conn.execute(query, params)
    rows = cursor.fetchall()
    return [procmon_event_from_row(row) for row in rows]


def query_events_for_session_ip_first(
    conn: sqlite3.Connection,
    ip_candidates: List[str],
    hostname_candidates: List[str],
    lower_bound: int,
    upper_bound: int,
    center_ts_us: int,
    limit: int,
) -> List[ProcmonEvent]:
    if not ip_candidates and not hostname_candidates:
        return []

    ip_placeholders = ", ".join("?" for _ in ip_candidates) if ip_candidates else ""
    host_placeholders = ", ".join("?" for _ in hostname_candidates) if hostname_candidates else ""
    conditions: List[str] = []
    if ip_candidates:
        conditions.append(f"remote_ip IN ({ip_placeholders})")
        conditions.append(f"local_ip IN ({ip_placeholders})")
    if hostname_candidates:
        conditions.append(f"remote_ip IN ({host_placeholders})")
    endpoint_clause = " OR ".join(conditions) if conditions else "1=1"
    query = f"""
        SELECT event_id, ts_us, pid, tid, process_name, process_path, command_line, user_name, company, parent_pid,
               integrity_level, signer, image_hash, operation, result, path, detail, proto, local_ip, local_port, remote_ip, remote_port, direction
        FROM procmon_events
        WHERE ts_us BETWEEN ? AND ?
          AND ({endpoint_clause})
        ORDER BY ABS(ts_us - ?) ASC
        LIMIT ?
    """
    params: List[object] = [lower_bound, upper_bound]
    if ip_candidates:
        params.extend(ip_candidates)
        params.extend(ip_candidates)
    if hostname_candidates:
        params.extend(hostname_candidates)
    params.extend([center_ts_us, limit])
    rows = conn.execute(query, params).fetchall()
    return [procmon_event_from_row(row) for row in rows]


def procmon_event_from_row(row: Sequence[object]) -> ProcmonEvent:
    return ProcmonEvent(
        event_id=str(row[0]),
        ts_us=int(row[1]),
        pid=row[2],  # type: ignore[arg-type]
        tid=row[3],  # type: ignore[arg-type]
        process_name=row[4],  # type: ignore[arg-type]
        process_path=row[5],  # type: ignore[arg-type]
        command_line=row[6],  # type: ignore[arg-type]
        user_name=row[7],  # type: ignore[arg-type]
        company=row[8],  # type: ignore[arg-type]
        parent_pid=row[9],  # type: ignore[arg-type]
        integrity_level=row[10],  # type: ignore[arg-type]
        signer=row[11],  # type: ignore[arg-type]
        image_hash=row[12],  # type: ignore[arg-type]
        operation=row[13],  # type: ignore[arg-type]
        result=row[14],  # type: ignore[arg-type]
        path=row[15],  # type: ignore[arg-type]
        detail=row[16],  # type: ignore[arg-type]
        proto=str(row[17] or "UNKNOWN"),
        local_ip=row[18],  # type: ignore[arg-type]
        local_port=row[19],  # type: ignore[arg-type]
        remote_ip=row[20],  # type: ignore[arg-type]
        remote_port=row[21],  # type: ignore[arg-type]
        direction=str(row[22] or "unknown"),
    )


def endpoint_pairs(session: SessionRecord) -> List[Tuple[str, int]]:
    pairs: List[Tuple[str, int]] = []
    if session.src_port is not None:
        pairs.append((session.src_ip, session.src_port))
    if session.dst_port is not None:
        pairs.append((session.dst_ip, session.dst_port))
    deduped: List[Tuple[str, int]] = []
    seen = set()
    for pair in pairs:
        if pair in seen:
            continue
        seen.add(pair)
        deduped.append(pair)
    return deduped


def session_public_ips(session: SessionRecord) -> List[str]:
    return dedupe_preserve_order([ip for ip in [session.src_ip, session.dst_ip] if ip and not is_private_ip(ip)])


def event_has_pcap_ip_anchor(
    session: SessionRecord,
    event: ProcmonEvent,
    dns_ips_by_host: Optional[Dict[str, Set[str]]],
) -> bool:
    public_ips = session_public_ips(session)
    if not public_ips:
        return True
    for expected_ip in public_ips:
        if event_endpoint_matches_ip(event, expected_ip, dns_ips_by_host):
            return True
    return False


def event_endpoint_matches_ip(
    event: ProcmonEvent,
    expected_ip: str,
    dns_ips_by_host: Optional[Dict[str, Set[str]]],
) -> bool:
    if event.remote_ip == expected_ip or event.local_ip == expected_ip:
        return True
    if remote_endpoint_matches_ip(event.remote_ip, expected_ip, dns_ips_by_host):
        return True
    if remote_endpoint_matches_ip(event.local_ip, expected_ip, dns_ips_by_host):
        return True

    raw_text = " ".join(part for part in [event.path, event.detail, event.remote_ip, event.local_ip] if part)
    return contains_ip_literal(raw_text, expected_ip)


def contains_ip_literal(text: str, ip: str) -> bool:
    if not text or not ip:
        return False
    if ":" in ip:
        lowered = text.lower()
        needle = ip.lower()
        return needle in lowered or f"[{needle}]" in lowered
    pattern = rf"(?<![0-9]){re.escape(ip)}(?![0-9])"
    return re.search(pattern, text) is not None


def score_session_event(
    session: SessionRecord,
    event: ProcmonEvent,
    time_offset_us: int,
    time_window_us: int,
    dns_ips_by_host: Optional[Dict[str, Set[str]]] = None,
) -> Tuple[int, int, List[Dict[str, object]]]:
    score = 0
    reasons: List[Dict[str, object]] = []
    offset_us = event.ts_us - (session.center_ts_us + time_offset_us)

    if not event_has_pcap_ip_anchor(session, event, dns_ips_by_host):
        return 0, offset_us, [{"code": "pcap_anchor_miss", "score": 0, "detail": "Brak wspolnego IP PCAP<->Procmon."}]

    shape = infer_session_shape(session)

    remote_exact_score = 0
    remote_ip_matches = remote_endpoint_matches_ip(event.remote_ip, shape.remote_ip, dns_ips_by_host)
    if shape.remote_ip and shape.remote_port is not None and remote_ip_matches and event.remote_port == shape.remote_port:
        remote_exact_score = 45
    if remote_exact_score:
        score += remote_exact_score
        reasons.append({"code": "endpoint_exact", "score": remote_exact_score, "detail": "Zgodnosc zdalnego IP:port."})

    remote_ip_score = 0
    if shape.remote_ip and remote_ip_matches and remote_exact_score == 0:
        remote_ip_score = 20
    if remote_ip_score:
        score += remote_ip_score
        reasons.append({"code": "remote_ip", "score": remote_ip_score, "detail": "Zgodnosc zdalnego IP."})

    remote_port_score = 0
    if shape.remote_port is not None and event.remote_port == shape.remote_port and remote_exact_score == 0:
        remote_port_score = 10
    if remote_port_score:
        score += remote_port_score
        reasons.append({"code": "remote_port", "score": remote_port_score, "detail": "Zgodnosc zdalnego portu."})

    local_port_score = 30 if shape.local_port is not None and event.local_port == shape.local_port else 0
    if local_port_score:
        score += local_port_score
        reasons.append({"code": "local_port", "score": local_port_score, "detail": "Zgodnosc portu lokalnego."})

    local_ip_score = 0
    if shape.local_ip and event.local_ip and event.local_ip == shape.local_ip:
        local_ip_score = 8
    if local_ip_score:
        score += local_ip_score
        reasons.append({"code": "local_ip", "score": local_ip_score, "detail": "Zgodnosc lokalnego IP."})

    delta = abs(offset_us)
    if delta <= time_window_us:
        time_score = int(round(20 * (1 - (delta / max(1, time_window_us)))))
        score += time_score
        reasons.append({"code": "time", "score": time_score, "detail": f"Roznica czasu {delta / 1000:.1f} ms."})

    direction_score = score_direction(session, event)
    if direction_score:
        score += direction_score
        reasons.append({"code": "direction", "score": direction_score, "detail": f"Kierunek {event.direction} zgodny z flow."})

    volume_score = 4 if session.byte_count > 0 and event.operation else 0
    if volume_score:
        score += volume_score
        reasons.append({"code": "volume", "score": volume_score, "detail": "Wolumen ruchu obecny po obu stronach."})

    return min(score, 100), offset_us, reasons


def score_direction(session: SessionRecord, event: ProcmonEvent) -> int:
    shape = infer_session_shape(session)
    if shape.direction == "unknown":
        return 0
    if event.direction == shape.direction:
        return 8
    if event.direction == "unknown":
        return 3
    return 0


def remote_endpoint_matches_ip(
    remote_value: Optional[str],
    expected_ip: Optional[str],
    dns_ips_by_host: Optional[Dict[str, Set[str]]],
) -> bool:
    if not remote_value or not expected_ip:
        return False
    if remote_value == expected_ip:
        return True
    if not dns_ips_by_host:
        return False
    hostname = normalize_hostname(remote_value)
    if not hostname:
        return False
    return expected_ip in dns_ips_by_host.get(hostname, set())


def normalize_hostname(value: str) -> Optional[str]:
    text = (value or "").strip().strip(".").lower()
    if not text:
        return None
    return text


def max_weight_matching(
    total_sessions: int,
    event_by_index: List[ProcmonEvent],
    candidate_edges: List[CandidateEdge],
    on_progress: ProgressCallback,
    event_capacity: int = 1,
    session_indices: Optional[Sequence[int]] = None,
    event_capacity_by_index: Optional[Dict[int, int]] = None,
    progress_label: str = "Matching",
) -> List[CandidateEdge]:
    active_sessions: List[int] = list(session_indices) if session_indices is not None else list(range(total_sessions))
    if not active_sessions or not candidate_edges:
        return []
    session_pos: Dict[int, int] = {session_idx: pos for pos, session_idx in enumerate(active_sessions)}

    total_events = len(event_by_index)
    source = 0
    session_offset = 1
    event_offset = session_offset + len(active_sessions)
    sink = event_offset + total_events
    node_count = sink + 1

    graph: List[List[Edge]] = [[] for _ in range(node_count)]

    def add_edge(u: int, v: int, cap: int, cost: int) -> int:
        forward = Edge(to=v, rev=len(graph[v]), cap=cap, cost=cost)
        backward = Edge(to=u, rev=len(graph[u]), cap=0, cost=-cost)
        graph[u].append(forward)
        graph[v].append(backward)
        return len(graph[u]) - 1

    for local_session_idx in range(len(active_sessions)):
        add_edge(source, session_offset + local_session_idx, 1, 0)
    for event_idx in range(total_events):
        event_cap = max(0, event_capacity_by_index.get(event_idx, event_capacity)) if event_capacity_by_index else event_capacity
        if event_cap <= 0:
            continue
        add_edge(event_offset + event_idx, sink, max(1, event_cap), 0)

    edge_refs: List[Tuple[int, int, CandidateEdge]] = []
    for edge in candidate_edges:
        local_session_idx = session_pos.get(edge.session_idx)
        if local_session_idx is None:
            continue
        u = session_offset + local_session_idx
        v = event_offset + edge.event_idx
        edge_index = add_edge(u, v, 1, -edge.score)
        edge_refs.append((u, edge_index, edge))

    total_flow = 0
    iteration = 0
    while True:
        iteration += 1
        dist = [math.inf] * node_count
        in_queue = [False] * node_count
        prev_node = [-1] * node_count
        prev_edge = [-1] * node_count

        dist[source] = 0
        queue = deque([source])
        in_queue[source] = True

        while queue:
            u = queue.popleft()
            in_queue[u] = False
            for edge_idx, edge in enumerate(graph[u]):
                if edge.cap <= 0:
                    continue
                v = edge.to
                new_dist = dist[u] + edge.cost
                if new_dist < dist[v]:
                    dist[v] = new_dist
                    prev_node[v] = u
                    prev_edge[v] = edge_idx
                    if not in_queue[v]:
                        queue.append(v)
                        in_queue[v] = True

        if prev_node[sink] == -1:
            break

        if dist[sink] >= 0:
            break

        v = sink
        while v != source:
            u = prev_node[v]
            edge_idx = prev_edge[v]
            edge = graph[u][edge_idx]
            edge.cap -= 1
            graph[v][edge.rev].cap += 1
            v = u
        total_flow += 1

        if iteration % 250 == 0:
            on_progress(iteration, max(1, len(candidate_edges)), f"{progress_label}: {iteration:,} iteracji")

    selected: List[CandidateEdge] = []
    for u, edge_idx, candidate in edge_refs:
        if graph[u][edge_idx].cap == 0:
            selected.append(candidate)
    return selected


def build_report(
    analysis_id: str,
    pcap_file_path: str,
    procmon_files: Sequence[str],
    parser_mode: str,
    warnings: List[str],
    time_offset_us: int,
    drift: float,
    sessions: List[SessionRecord],
    event_by_index: List[ProcmonEvent],
    selected_edges: List[CandidateEdge],
    total_procmon_events: int,
) -> Dict[str, object]:
    session_to_edge: Dict[int, CandidateEdge] = {edge.session_idx: edge for edge in selected_edges}
    event_to_edge: Dict[int, CandidateEdge] = {edge.event_idx: edge for edge in selected_edges}

    matches: List[Dict[str, object]] = []
    unmatched_sessions: List[Dict[str, object]] = []
    unmatched_events: List[Dict[str, object]] = []

    for session_idx, session in enumerate(sessions):
        edge = session_to_edge.get(session_idx)
        if not edge:
            unmatched_sessions.append(
                {
                    "sessionId": session.session_id,
                    "protocol": session.proto,
                    "srcIp": session.src_ip,
                    "srcPort": session.src_port,
                    "dstIp": session.dst_ip,
                    "dstPort": session.dst_port,
                    "firstSeenUs": session.first_ts_us,
                    "lastSeenUs": session.last_ts_us,
                    "packets": session.packet_count,
                    "bytes": session.byte_count,
                    "reason": "No candidate above threshold.",
                }
            )
            continue

        event = event_by_index[edge.event_idx]
        matches.append(
            {
                "sessionId": session.session_id,
                "protocol": session.proto,
                "srcIp": session.src_ip,
                "srcPort": session.src_port,
                "dstIp": session.dst_ip,
                "dstPort": session.dst_port,
                "firstSeenUs": session.first_ts_us,
                "lastSeenUs": session.last_ts_us,
                "packets": session.packet_count,
                "bytes": session.byte_count,
                "eventId": event.event_id,
                "matchedAtUs": event.ts_us,
                "pid": event.pid,
                "tid": event.tid,
                "processName": event.process_name,
                "processPath": event.process_path,
                "commandLine": event.command_line,
                "userName": event.user_name,
                "company": event.company,
                "parentPid": event.parent_pid,
                "integrityLevel": event.integrity_level,
                "signer": event.signer,
                "imageHash": event.image_hash,
                "operation": event.operation,
                "result": event.result,
                "eventLocalIp": event.local_ip,
                "eventLocalPort": event.local_port,
                "eventRemoteIp": event.remote_ip,
                "eventRemotePort": event.remote_port,
                "eventDirection": event.direction,
                "score": edge.score,
                "confidence": score_to_confidence(edge.score),
                "offsetUs": edge.offset_us,
                "reasons": edge.reasons,
            }
        )

    for event_idx, event in enumerate(event_by_index):
        if event_idx in event_to_edge:
            continue
        unmatched_events.append(
            {
                "eventId": event.event_id,
                "tsUs": event.ts_us,
                "pid": event.pid,
                "processName": event.process_name,
                "processPath": event.process_path,
                "commandLine": event.command_line,
                "userName": event.user_name,
                "company": event.company,
                "parentPid": event.parent_pid,
                "integrityLevel": event.integrity_level,
                "signer": event.signer,
                "imageHash": event.image_hash,
                "operation": event.operation,
                "eventLocalIp": event.local_ip,
                "eventLocalPort": event.local_port,
                "remoteIp": event.remote_ip,
                "remotePort": event.remote_port,
                "eventDirection": event.direction,
                "reason": "No session match.",
            }
        )

    diagnostics = {
        "timeOffsetUs": time_offset_us,
        "drift": drift,
        "totalSessions": len(sessions),
        "totalProcmonEvents": total_procmon_events,
        "matchedSessions": len(matches),
        "unmatchedSessions": len(unmatched_sessions),
        "unmatchedProcmonEvents": max(total_procmon_events - len(event_to_edge), 0),
        "parserMode": parser_mode,
        "warnings": warnings,
    }

    return {
        "schema": "correlation_report_v1",
        "version": 1,
        "generatedAt": iso_now(),
        "analysisId": analysis_id,
        "pcapFilePath": pcap_file_path,
        "procmonFiles": list(procmon_files),
        "diagnostics": diagnostics,
        "matches": matches,
        "unmatchedSessions": unmatched_sessions,
        "unmatchedProcmonEvents": unmatched_events,
        "warnings": warnings,
    }


def score_to_confidence(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 60:
        return "medium"
    if score >= 45:
        return "low"
    return "unmatched"


def infer_session_shape(session: SessionRecord) -> SessionShape:
    src_private = is_private_ip(session.src_ip)
    dst_private = is_private_ip(session.dst_ip)

    if src_private and not dst_private:
        return SessionShape(
            local_ip=session.src_ip,
            local_port=session.src_port,
            remote_ip=session.dst_ip,
            remote_port=session.dst_port,
            direction="outbound",
        )
    if dst_private and not src_private:
        return SessionShape(
            local_ip=session.dst_ip,
            local_port=session.dst_port,
            remote_ip=session.src_ip,
            remote_port=session.src_port,
            direction="inbound",
        )

    return SessionShape(
        local_ip=session.src_ip,
        local_port=session.src_port,
        remote_ip=session.dst_ip,
        remote_port=session.dst_port,
        direction="unknown",
    )


def iso_now() -> str:
    import datetime as dt

    return dt.datetime.now(dt.timezone.utc).isoformat()
