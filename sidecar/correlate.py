from __future__ import annotations

import json
import math
import sqlite3
import statistics
from collections import deque
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

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
    operation: Optional[str]
    result: Optional[str]
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

    if total_sessions == 0:
        raise RuntimeError("Brak sesji PCAP do korelacji.")

    if total_procmon_events == 0:
        raise RuntimeError("Brak eventow sieciowych Procmon do korelacji.")

    on_progress(0, max(1, total_sessions), "Szacowanie synchronizacji czasu PCAP <-> Procmon")
    time_offset_us = estimate_time_offset(conn, sessions)
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

    if not edges:
        warnings.append("Nie znaleziono kandydatow dopasowania przy obecnych progach.")
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
            selected_edges=[],
            total_procmon_events=total_procmon_events,
        )

    on_progress(0, max(1, len(edges)), "Globalny matching (max-weight)")
    selected_edges = max_weight_matching(
        total_sessions=total_sessions,
        event_by_index=event_by_index,
        candidate_edges=edges,
        on_progress=on_progress,
        event_capacity=32,
    )

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

        event_rows = query_events_for_session(
            conn=conn,
            proto=session.proto,
            remote_pairs=remote_pairs or endpoint_pairs_all,
            local_ports=local_ports,
            ip_candidates=ip_candidates,
            lower_bound=lower_bound,
            upper_bound=upper_bound,
            limit=max(max_candidates * 64, 256),
        )
        scored: List[Tuple[int, Dict[str, object], ProcmonEvent]] = []
        for event in event_rows:
            score, offset_us, reasons = score_session_event(session, event, time_offset_us, time_window_us)
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


def query_events_for_session(
    conn: sqlite3.Connection,
    proto: str,
    remote_pairs: List[Tuple[str, int]],
    local_ports: List[int],
    ip_candidates: List[str],
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

    endpoint_sql = " OR ".join(clauses) if clauses else "1=1"
    query = f"""
        SELECT event_id, ts_us, pid, tid, process_name, operation, result, proto, local_ip, local_port, remote_ip, remote_port, direction
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
    events: List[ProcmonEvent] = []
    for row in rows:
        events.append(
            ProcmonEvent(
                event_id=row[0],
                ts_us=row[1],
                pid=row[2],
                tid=row[3],
                process_name=row[4],
                operation=row[5],
                result=row[6],
                proto=row[7],
                local_ip=row[8],
                local_port=row[9],
                remote_ip=row[10],
                remote_port=row[11],
                direction=row[12] or "unknown",
            )
        )
    return events


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


def score_session_event(
    session: SessionRecord,
    event: ProcmonEvent,
    time_offset_us: int,
    time_window_us: int,
) -> Tuple[int, int, List[Dict[str, object]]]:
    score = 0
    reasons: List[Dict[str, object]] = []
    offset_us = event.ts_us - (session.center_ts_us + time_offset_us)
    shape = infer_session_shape(session)

    remote_exact_score = 0
    if (
        shape.remote_ip
        and shape.remote_port is not None
        and event.remote_ip == shape.remote_ip
        and event.remote_port == shape.remote_port
    ):
        remote_exact_score = 45
    if remote_exact_score:
        score += remote_exact_score
        reasons.append({"code": "endpoint_exact", "score": remote_exact_score, "detail": "Zgodnosc zdalnego IP:port."})

    remote_ip_score = 0
    if shape.remote_ip and event.remote_ip == shape.remote_ip and remote_exact_score == 0:
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


def max_weight_matching(
    total_sessions: int,
    event_by_index: List[ProcmonEvent],
    candidate_edges: List[CandidateEdge],
    on_progress: ProgressCallback,
    event_capacity: int = 1,
) -> List[CandidateEdge]:
    total_events = len(event_by_index)
    source = 0
    session_offset = 1
    event_offset = session_offset + total_sessions
    sink = event_offset + total_events
    node_count = sink + 1

    graph: List[List[Edge]] = [[] for _ in range(node_count)]

    def add_edge(u: int, v: int, cap: int, cost: int) -> int:
        forward = Edge(to=v, rev=len(graph[v]), cap=cap, cost=cost)
        backward = Edge(to=u, rev=len(graph[u]), cap=0, cost=-cost)
        graph[u].append(forward)
        graph[v].append(backward)
        return len(graph[u]) - 1

    for session_idx in range(total_sessions):
        add_edge(source, session_offset + session_idx, 1, 0)
    for event_idx in range(total_events):
        add_edge(event_offset + event_idx, sink, max(1, event_capacity), 0)

    edge_refs: List[Tuple[int, int, CandidateEdge]] = []
    for edge in candidate_edges:
        u = session_offset + edge.session_idx
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
            on_progress(iteration, max(1, len(candidate_edges)), f"Matching: {iteration:,} iteracji")

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
                "operation": event.operation,
                "result": event.result,
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
                "operation": event.operation,
                "remoteIp": event.remote_ip,
                "remotePort": event.remote_port,
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
