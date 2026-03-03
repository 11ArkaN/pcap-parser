from __future__ import annotations

import csv
import datetime as dt
import gzip
import hashlib
import json
import math
import multiprocessing as mp
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from common import is_private_ip, normalize_ip, parse_int, parse_procmon_timestamp

ProgressCallback = Callable[[int, int, str], None]

IPV4_ENDPOINT_RE = re.compile(r"(?<!\d)(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})")
IPV6_ENDPOINT_RE = re.compile(r"\[([0-9a-fA-F:]+)\]:(\d{1,5})")

NETWORK_OPERATION_KEYWORDS = (
    "tcp",
    "udp",
    "connect",
    "disconnect",
    "send",
    "receive",
    "bind",
    "listen",
    "reconnect",
)

SERVICE_PORTS = {
    "http": 80,
    "https": 443,
    "dns": 53,
    "llmnr": 5355,
    "mdns": 5353,
    "ntp": 123,
    "ldap": 389,
    "ldaps": 636,
    "smb": 445,
    "ssh": 22,
    "imap": 143,
    "imaps": 993,
    "smtp": 25,
    "smtps": 465,
    "pop3": 110,
    "pop3s": 995,
}

PROC_MON_CACHE_VERSION = "v2"
BATCH_SIZE = 5000
PROCMON_DB_COLUMNS: Tuple[str, ...] = (
    "event_id",
    "ts_us",
    "pid",
    "tid",
    "process_name",
    "process_path",
    "command_line",
    "user_name",
    "company",
    "parent_pid",
    "integrity_level",
    "signer",
    "image_hash",
    "operation",
    "result",
    "path",
    "detail",
    "proto",
    "local_ip",
    "local_port",
    "remote_ip",
    "remote_port",
    "direction",
    "source_file",
)
_PARSER_AVAILABLE: Optional[bool] = None
PARALLEL_PARSE_MIN_ITEMS = 120_000
DEFAULT_MAX_PROC_WORKERS = 8


def ingest_procmon_to_sqlite(
    procmon_files: List[str],
    procmon_executable: str,
    conn: sqlite3.Connection,
    output_dir: str,
    on_progress: ProgressCallback,
) -> Dict[str, object]:
    warnings: List[str] = []
    total_events = 0
    cli_used = False
    parser_used = False

    exports_dir = Path(output_dir) / "procmon_exports"
    exports_dir.mkdir(parents=True, exist_ok=True)
    cache_dir = resolve_cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)

    can_use_procmon_parser = ensure_procmon_parser_available()
    if not can_use_procmon_parser:
        warnings.append("Biblioteka procmon-parser niedostepna.")

    total_files = max(1, len(procmon_files))
    for index, pml_path in enumerate(procmon_files, start=1):
        pml_file = Path(pml_path)
        if not pml_file.exists():
            warnings.append(f"Plik Procmon nie istnieje: {pml_path}")
            continue

        base_date = dt.datetime.fromtimestamp(os.path.getmtime(pml_path), tz=dt.timezone.utc).date()
        cache_key = build_procmon_cache_key(pml_path)
        cache_path = cache_dir / f"{cache_key}.jsonl.gz"
        inserted_for_file = 0
        export_messages: List[str] = []
        used_cache = False

        if cache_path.exists():
            inserted_from_cache = load_cached_events_to_db(
                conn=conn,
                cache_path=cache_path,
                source_pml_path=pml_path,
                on_progress=on_progress,
                file_index=index,
                total_files=total_files,
            )
            if inserted_from_cache > 0:
                inserted_for_file += inserted_from_cache
                parser_used = True
                used_cache = True
                on_progress(index, total_files, f"Cache Procmon: zaladowano {inserted_from_cache:,} eventow")

        if inserted_for_file == 0 and can_use_procmon_parser:
            inserted = parse_pml_with_procmon_parser_to_db(
                conn=conn,
                pml_path=pml_path,
                event_id_prefix=f"{pml_file.name}|parser|{index}|",
                base_date=base_date,
                on_progress=on_progress,
                file_index=index,
                total_files=total_files,
            )
            if inserted > 0:
                parser_used = True
            inserted_for_file += inserted

        if inserted_for_file == 0:
            csv_path = exports_dir / f"{pml_file.stem}-{index}.csv"
            csv_ok, csv_details = export_pml(procmon_executable, pml_file, csv_path, output_kind="csv")
            if csv_ok:
                cli_used = True
                inserted = parse_csv_to_db(
                    conn=conn,
                    csv_path=str(csv_path),
                    source_pml_path=pml_path,
                    event_id_prefix=f"{pml_file.name}|csv|{index}|",
                    base_date=base_date,
                    on_progress=on_progress,
                    file_index=index,
                    total_files=total_files,
                )
                inserted_for_file += inserted
            else:
                export_messages.append(f"CSV export failed: {csv_details}")

        if inserted_for_file == 0:
            xml_path = exports_dir / f"{pml_file.stem}-{index}.xml"
            xml_ok, xml_details = export_pml(procmon_executable, pml_file, xml_path, output_kind="xml")
            if xml_ok:
                cli_used = True
                inserted = parse_xml_to_db(
                    conn=conn,
                    xml_path=str(xml_path),
                    source_pml_path=pml_path,
                    event_id_prefix=f"{pml_file.name}|xml|{index}|",
                    base_date=base_date,
                    on_progress=on_progress,
                    file_index=index,
                    total_files=total_files,
                )
                inserted_for_file += inserted
            else:
                export_messages.append(f"XML export failed: {xml_details}")

        if inserted_for_file > 0 and not used_cache:
            try:
                cached_count = write_source_events_cache(conn, source_pml_path=pml_path, cache_path=cache_path)
                if cached_count <= 0:
                    warnings.append(f"Nie zapisano cache Procmon dla {pml_path}.")
            except Exception as error:
                warnings.append(f"Blad zapisu cache Procmon ({pml_path}): {error}")

        if inserted_for_file == 0:
            warning = f"Brak eventow sieciowych z pliku {pml_path}."
            if export_messages:
                warning += " " + " | ".join(export_messages)
            warnings.append(warning)

        total_events += inserted_for_file
        conn.commit()
        on_progress(index, total_files, f"Procmon: {index}/{total_files} plikow, eventy: {total_events:,}")

    parser_mode = "xml_only"
    if cli_used and parser_used:
        parser_mode = "hybrid"
    elif parser_used and not cli_used:
        parser_mode = "parser_only"

    conn.commit()
    return {
        "total_events": total_events,
        "parser_mode": parser_mode,
        "warnings": warnings,
    }


def ensure_procmon_parser_available() -> bool:
    global _PARSER_AVAILABLE
    if _PARSER_AVAILABLE is not None:
        return _PARSER_AVAILABLE
    try:
        import procmon_parser  # type: ignore  # noqa: F401

        _PARSER_AVAILABLE = True
        return True
    except Exception:
        _PARSER_AVAILABLE = False
        return False


def resolve_parallel_worker_count(total_reader_items: int) -> int:
    if total_reader_items < PARALLEL_PARSE_MIN_ITEMS:
        return 1

    cpu_total = os.cpu_count() or 2
    env_workers = parse_int(os.getenv("PCAP_ANALYZER_PROCMON_WORKERS"))
    target = env_workers if env_workers and env_workers > 0 else max(1, cpu_total - 1)
    target = min(target, DEFAULT_MAX_PROC_WORKERS)

    max_meaningful = max(1, total_reader_items // 80_000)
    return max(1, min(target, max_meaningful))


def resolve_cache_dir() -> Path:
    env_dir = os.getenv("PCAP_ANALYZER_PROCMON_CACHE_DIR")
    if env_dir:
        return Path(env_dir)
    return Path(tempfile.gettempdir()) / "pcap-analyzer-procmon-cache"


def build_procmon_cache_key(pml_path: str) -> str:
    stat = os.stat(pml_path)
    payload = f"{PROC_MON_CACHE_VERSION}|{os.path.abspath(pml_path)}|{stat.st_size}|{stat.st_mtime_ns}"
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


def load_cached_events_to_db(
    conn: sqlite3.Connection,
    cache_path: Path,
    source_pml_path: str,
    on_progress: ProgressCallback,
    file_index: int,
    total_files: int,
) -> int:
    inserted_rows: List[Tuple[object, ...]] = []
    inserted_count = 0
    with gzip.open(cache_path, "rt", encoding="utf-8") as handle:
        for line_index, line in enumerate(handle, start=1):
            raw = line.strip()
            if not raw:
                continue
            record = json.loads(raw)
            if not isinstance(record, dict):
                continue
            row_values: List[object] = []
            for column in PROCMON_DB_COLUMNS:
                if column == "source_file":
                    row_values.append(source_pml_path)
                else:
                    row_values.append(record.get(column))
            inserted_rows.append(tuple(row_values))
            inserted_count += 1

            if len(inserted_rows) >= BATCH_SIZE:
                write_procmon_rows(conn, inserted_rows)
                inserted_rows.clear()
                if inserted_count % (BATCH_SIZE * 2) == 0:
                    on_progress(file_index, total_files, f"Cache Procmon: {inserted_count:,} eventow")

            if line_index % 100000 == 0:
                on_progress(file_index, total_files, f"Cache Procmon: odczyt {line_index:,} linii")

    if inserted_rows:
        write_procmon_rows(conn, inserted_rows)

    return inserted_count


def write_source_events_cache(conn: sqlite3.Connection, source_pml_path: str, cache_path: Path) -> int:
    query = f"""
        SELECT {", ".join(PROCMON_DB_COLUMNS)}
        FROM procmon_events
        WHERE source_file = ?
        ORDER BY ts_us ASC
    """
    cursor = conn.execute(query, (source_pml_path,))
    rows = cursor.fetchall()
    if not rows:
        return 0
    with gzip.open(cache_path, "wt", encoding="utf-8") as handle:
        for row in rows:
            payload = {column: row[idx] for idx, column in enumerate(PROCMON_DB_COLUMNS)}
            handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
    return len(rows)


def export_pml(procmon_executable: str, pml_path: Path, output_path: Path, output_kind: str) -> Tuple[bool, str]:
    if output_path.exists():
        try:
            output_path.unlink()
        except Exception:
            pass

    commands = build_export_commands(procmon_executable, pml_path, output_path, output_kind)
    results: List[str] = []

    try:
        subprocess.run([procmon_executable, "/AcceptEula", "/Terminate"], capture_output=True, text=True, timeout=30, check=False)
        time.sleep(0.3)
    except Exception:
        pass

    for command in commands:
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=360, check=False)
            time.sleep(0.4)
            if output_path.exists() and output_path.stat().st_size > 0:
                return True, "ok"
            stdout = (completed.stdout or "").strip().replace("\n", " ")[:180]
            stderr = (completed.stderr or "").strip().replace("\n", " ")[:180]
            details = f"rc={completed.returncode}"
            if stdout:
                details += f", out={stdout}"
            if stderr:
                details += f", err={stderr}"
            results.append(details)
        except Exception as error:
            results.append(f"exception={error}")

    return False, "; ".join(results[-3:]) if results else "no command executed"


def build_export_commands(procmon_executable: str, pml_path: Path, output_path: Path, output_kind: str) -> List[List[str]]:
    output = str(output_path)
    base = [procmon_executable, "/AcceptEula", "/OpenLog", str(pml_path)]
    commands: List[List[str]] = []

    if output_kind == "csv":
        commands.append(base + ["/SaveAs", output, "/Terminate"])
        commands.append([procmon_executable, "/AcceptEula", "/Quiet", "/OpenLog", str(pml_path), "/SaveAs", output, "/Terminate"])
        commands.append(base + ["/SaveAs2", output, "/Terminate"])
        commands.append([procmon_executable, "/AcceptEula", "/Run32", "/OpenLog", str(pml_path), "/SaveAs", output, "/Terminate"])
    else:
        commands.append(base + ["/SaveAs2", output, "/Terminate"])
        commands.append([procmon_executable, "/AcceptEula", "/Quiet", "/OpenLog", str(pml_path), "/SaveAs2", output, "/Terminate"])
        commands.append(base + ["/SaveAs", output, "/Terminate"])
        commands.append([procmon_executable, "/AcceptEula", "/Run32", "/OpenLog", str(pml_path), "/SaveAs2", output, "/Terminate"])

    return commands


def parse_csv_to_db(
    conn: sqlite3.Connection,
    csv_path: str,
    source_pml_path: str,
    event_id_prefix: str,
    base_date: dt.date,
    on_progress: ProgressCallback,
    file_index: int,
    total_files: int,
) -> int:
    inserted_rows: List[Tuple[object, ...]] = []
    inserted_count = 0

    with open(csv_path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        sample = handle.read(4096)
        handle.seek(0)

        delimiter = ","
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            delimiter = dialect.delimiter
        except Exception:
            delimiter = ";" if sample.count(";") > sample.count(",") else ","

        reader = csv.DictReader(handle, delimiter=delimiter)
        if not reader.fieldnames:
            return 0

        for row_index, row in enumerate(reader, start=1):
            record = {normalize_key(str(key)): (value or "").strip() for key, value in row.items() if key is not None}
            row_data = record_to_db_row(
                record=record,
                base_date=base_date,
                event_id=f"{event_id_prefix}{row_index}",
                source_pml_path=source_pml_path,
            )
            if not row_data:
                continue
            inserted_rows.append(row_data)
            inserted_count += 1

            if len(inserted_rows) >= BATCH_SIZE:
                write_procmon_rows(conn, inserted_rows)
                inserted_rows.clear()
                on_progress(file_index, total_files, f"Procmon CSV: {inserted_count:,} eventow sieciowych")

    if inserted_rows:
        write_procmon_rows(conn, inserted_rows)

    return inserted_count


def parse_xml_to_db(
    conn: sqlite3.Connection,
    xml_path: str,
    source_pml_path: str,
    event_id_prefix: str,
    base_date: dt.date,
    on_progress: ProgressCallback,
    file_index: int,
    total_files: int,
) -> int:
    inserted_rows: List[Tuple[object, ...]] = []
    inserted_count = 0

    context = ET.iterparse(xml_path, events=("end",))
    for _, elem in context:
        if elem.tag.lower() not in {"event", "row", "item"}:
            continue

        record = extract_record(elem)
        elem.clear()
        row_data = record_to_db_row(
            record=record,
            base_date=base_date,
            event_id=f"{event_id_prefix}{inserted_count + 1}",
            source_pml_path=source_pml_path,
        )
        if not row_data:
            continue

        inserted_rows.append(row_data)
        inserted_count += 1

        if len(inserted_rows) >= BATCH_SIZE:
            write_procmon_rows(conn, inserted_rows)
            inserted_rows.clear()
            on_progress(file_index, total_files, f"Procmon XML: {inserted_count:,} eventow sieciowych")

    if inserted_rows:
        write_procmon_rows(conn, inserted_rows)

    return inserted_count


def parse_pml_with_procmon_parser_to_db(
    conn: sqlite3.Connection,
    pml_path: str,
    event_id_prefix: str,
    base_date: dt.date,
    on_progress: ProgressCallback,
    file_index: int,
    total_files: int,
) -> int:
    try:
        from procmon_parser import ProcmonLogsReader  # type: ignore
    except Exception:
        return 0

    inserted_rows: List[Tuple[object, ...]] = []
    inserted_count = 0

    try:
        handle = open(pml_path, "rb")
        reader = ProcmonLogsReader(handle)
    except Exception:
        return 0

    try:
        try:
            total_reader_items = len(reader)
        except Exception:
            total_reader_items = 0

        worker_count = resolve_parallel_worker_count(total_reader_items)
        if total_reader_items > 0 and worker_count > 1:
            on_progress(
                file_index,
                total_files,
                f"procmon-parser: uruchamianie trybu rownoleglego ({worker_count} workerow, {total_reader_items:,} eventow)",
            )
            parallel_count = parse_pml_with_procmon_parser_parallel_to_db(
                conn=conn,
                pml_path=pml_path,
                event_id_prefix=event_id_prefix,
                base_date=base_date,
                on_progress=on_progress,
                file_index=file_index,
                total_files=total_files,
                total_reader_items=total_reader_items,
                worker_count=worker_count,
            )
            if parallel_count >= 0:
                on_progress(
                    file_index,
                    total_files,
                    f"procmon-parser: koniec trybu rownoleglego, eventy sieciowe: {parallel_count:,}",
                )
                return parallel_count
            on_progress(file_index, total_files, "procmon-parser: fallback do trybu sekwencyjnego")

        try:
            iterator = iter(reader)
            iterator_mode = True
        except Exception:
            iterator_mode = False

        idx = -1
        while True:
            idx += 1
            try:
                if iterator_mode:
                    event = next(iterator)
                else:
                    if total_reader_items <= 0 or idx >= total_reader_items:
                        break
                    event = reader[idx]
            except StopIteration:
                break
            except Exception:
                if (idx + 1) % 25000 == 0:
                    if total_reader_items > 0:
                        on_progress(
                            file_index,
                            total_files,
                            f"procmon-parser: skan {idx + 1:,}/{total_reader_items:,}, eventy sieciowe: {inserted_count:,}",
                        )
                    else:
                        on_progress(file_index, total_files, f"procmon-parser: skan {idx + 1:,}, eventy sieciowe: {inserted_count:,}")
                continue

            row_data = procmon_event_to_db_row(
                event=event,
                base_date=base_date,
                event_id=f"{event_id_prefix}{idx + 1}",
                source_pml_path=pml_path,
            )
            if not row_data:
                continue
            inserted_rows.append(row_data)
            inserted_count += 1

            if len(inserted_rows) >= BATCH_SIZE:
                write_procmon_rows(conn, inserted_rows)
                inserted_rows.clear()
                on_progress(file_index, total_files, f"procmon-parser: {inserted_count:,} eventow sieciowych")

            if (idx + 1) % 25000 == 0:
                if total_reader_items > 0:
                    on_progress(
                        file_index,
                        total_files,
                        f"procmon-parser: skan {idx + 1:,}/{total_reader_items:,}, eventy sieciowe: {inserted_count:,}",
                    )
                else:
                    on_progress(file_index, total_files, f"procmon-parser: skan {idx + 1:,}, eventy sieciowe: {inserted_count:,}")
    finally:
        try:
            handle.close()
        except Exception:
            pass

    if inserted_rows:
        write_procmon_rows(conn, inserted_rows)

    on_progress(file_index, total_files, f"procmon-parser: koniec skanu, eventy sieciowe: {inserted_count:,}")

    return inserted_count


def parse_pml_with_procmon_parser_parallel_to_db(
    conn: sqlite3.Connection,
    pml_path: str,
    event_id_prefix: str,
    base_date: dt.date,
    on_progress: ProgressCallback,
    file_index: int,
    total_files: int,
    total_reader_items: int,
    worker_count: int,
) -> int:
    if total_reader_items <= 0 or worker_count <= 1:
        return -1

    chunk_size = max(40_000, int(math.ceil(total_reader_items / worker_count)))
    ranges: List[Tuple[int, int]] = []
    start = 0
    while start < total_reader_items:
        end = min(total_reader_items, start + chunk_size)
        ranges.append((start, end))
        start = end

    if len(ranges) < 2:
        return -1

    tmp_dir = Path(tempfile.mkdtemp(prefix="pcap-procmon-parallel-"))
    tasks: List[Dict[str, object]] = []
    for part_idx, (part_start, part_end) in enumerate(ranges):
        tasks.append(
            {
                "pml_path": pml_path,
                "event_id_prefix": event_id_prefix,
                "base_date": base_date.isoformat(),
                "source_pml_path": pml_path,
                "start": part_start,
                "end": part_end,
                "out_path": str(tmp_dir / f"part-{part_idx:04d}.jsonl.gz"),
            }
        )

    inserted_total = 0
    try:
        ctx = mp.get_context("spawn")
        process_count = min(worker_count, len(tasks))
        with ctx.Pool(processes=process_count) as pool:
            completed = 0
            for out_path, raw_inserted, error in pool.imap_unordered(parse_procmon_chunk_to_cache, tasks):
                completed += 1
                if error:
                    raise RuntimeError(error)
                if out_path and raw_inserted > 0:
                    loaded = load_cached_events_to_db(
                        conn=conn,
                        cache_path=Path(out_path),
                        source_pml_path=pml_path,
                        on_progress=on_progress,
                        file_index=file_index,
                        total_files=total_files,
                    )
                    inserted_total += loaded
                on_progress(
                    file_index,
                    total_files,
                    f"procmon-parser parallel: fragment {completed:,}/{len(tasks):,}, eventy: {inserted_total:,}",
                )
        return inserted_total
    except Exception:
        return -1
    finally:
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass


def parse_procmon_chunk_to_cache(task: Dict[str, object]) -> Tuple[str, int, Optional[str]]:
    out_path = str(task.get("out_path") or "")
    try:
        from procmon_parser import ProcmonLogsReader  # type: ignore

        pml_path = str(task["pml_path"])
        event_id_prefix = str(task["event_id_prefix"])
        base_date = dt.date.fromisoformat(str(task["base_date"]))
        source_pml_path = str(task["source_pml_path"])
        start = int(task["start"])
        end = int(task["end"])

        inserted = 0
        with open(pml_path, "rb") as handle:
            reader = ProcmonLogsReader(handle)
            with gzip.open(out_path, "wt", encoding="utf-8") as out_handle:
                for idx in range(start, end):
                    try:
                        event = reader[idx]
                    except Exception:
                        continue
                    row = procmon_event_to_db_row(
                        event=event,
                        base_date=base_date,
                        event_id=f"{event_id_prefix}{idx + 1}",
                        source_pml_path=source_pml_path,
                    )
                    if not row:
                        continue
                    payload = {column: row[pos] for pos, column in enumerate(PROCMON_DB_COLUMNS)}
                    out_handle.write(json.dumps(payload, ensure_ascii=True) + "\n")
                    inserted += 1
        return out_path, inserted, None
    except Exception as error:
        try:
            if out_path and os.path.exists(out_path):
                os.remove(out_path)
        except Exception:
            pass
        return out_path, 0, str(error)


def procmon_event_to_db_row(
    event: Any,
    base_date: dt.date,
    event_id: str,
    source_pml_path: str,
) -> Optional[Tuple[object, ...]]:
    operation = stringify_attr(event, "operation")
    category = stringify_attr(event, "event_class")
    details_obj = getattr(event, "details", None)
    detail_text = stringify_details(details_obj)
    path_value = stringify_attr(event, "path")
    process_obj = getattr(event, "process", None)

    process_pid = parse_int(getattr(process_obj, "pid", None)) if process_obj is not None else None
    process_path = pick_first_attr(process_obj, ["image_path", "process_path", "path", "image"])
    process_name = pick_first_attr(process_obj, ["process_name", "name"]) or process_path
    command_line = pick_first_attr(process_obj, ["command_line", "cmdline", "commandline"])
    user_name = pick_first_attr(process_obj, ["user", "username", "user_name"])
    company = pick_first_attr(process_obj, ["company", "publisher"])
    parent_pid = parse_int(pick_first_attr(process_obj, ["parent_pid", "ppid", "parentprocessid"]))
    integrity_level = pick_first_attr(process_obj, ["integrity_level", "integrity", "integritylevel"])
    signer = pick_first_attr(process_obj, ["signer", "signature", "verified_signer"])
    image_hash = pick_first_attr(process_obj, ["sha256", "sha1", "hash", "image_hash"])

    record = {
        "operation": operation,
        "category": category,
        "detail": detail_text,
        "path": path_value,
        "result": stringify_attr(event, "result"),
        "pid": str(process_pid or parse_int(getattr(event, "pid", None)) or ""),
        "tid": str(parse_int(getattr(event, "tid", None)) or ""),
        "processname": process_name,
        "processpath": process_path,
        "commandline": command_line,
        "user": user_name,
        "company": company,
        "parentpid": str(parent_pid or ""),
        "integritylevel": integrity_level,
        "signer": signer,
        "hash": image_hash,
    }

    filetime_value = parse_int(getattr(event, "date_filetime", None))
    if filetime_value is not None:
        ts_us = filetime_to_epoch_us(filetime_value)
        record["timestamp"] = str(ts_us)
    else:
        date_attr = getattr(event, "date", None)
        if callable(date_attr):
            try:
                date_val = date_attr()
                record["time"] = str(date_val)
            except Exception:
                pass

    return record_to_db_row(
        record=record,
        base_date=base_date,
        event_id=event_id,
        source_pml_path=source_pml_path,
    )


def stringify_attr(obj: Any, attr_name: str) -> str:
    if obj is None:
        return ""
    try:
        value = getattr(obj, attr_name)
    except Exception:
        return ""
    if callable(value):
        try:
            value = value()
        except Exception:
            return ""
    if value is None:
        return ""
    return str(value)


def pick_first_attr(obj: Any, candidates: List[str]) -> str:
    for candidate in candidates:
        value = stringify_attr(obj, candidate)
        if value:
            return value
    return ""


def stringify_details(details_obj: Any) -> str:
    if details_obj is None:
        return ""
    if isinstance(details_obj, dict):
        parts = [f"{key}: {value}" for key, value in details_obj.items()]
        return ", ".join(parts)
    return str(details_obj)


def filetime_to_epoch_us(filetime_value: int) -> int:
    unix_epoch_filetime = 116444736000000000
    return (filetime_value - unix_epoch_filetime) // 10


def record_to_db_row(
    record: Dict[str, str],
    base_date: dt.date,
    event_id: str,
    source_pml_path: str,
) -> Optional[Tuple[object, ...]]:
    if not is_network_record(record):
        return None

    ts_us = extract_timestamp(record, base_date)
    if ts_us is None:
        return None

    operation = value_of(record, "operation")
    path = value_of(record, "path")
    detail = value_of(record, "detail")
    result = value_of(record, "result")
    process_name = value_of(record, "processname")
    process_path = value_any(record, ["processpath", "imagepath", "exepath", "processimagepath", "image"])
    command_line = value_any(record, ["commandline", "cmdline", "command"])
    user_name = value_any(record, ["user", "username", "accountname"])
    company = value_any(record, ["company", "publisher"])
    parent_pid = parse_int(value_any(record, ["parentpid", "parentprocessid", "ppid"]))
    integrity_level = value_any(record, ["integritylevel", "integrity"])
    signer = value_any(record, ["signer", "signature", "verifiedsigner"])
    image_hash = value_any(record, ["sha256", "sha1", "hash", "imagehash"])
    pid = parse_int(value_of(record, "pid"))
    tid = parse_int(value_of(record, "tid"))
    proto = operation_to_proto(operation)
    local_ip, local_port, remote_ip, remote_port, direction = extract_endpoints(operation, path, detail)

    if remote_ip is None and local_ip is None:
        return None

    return (
        event_id,
        ts_us,
        pid,
        tid,
        process_name,
        process_path,
        command_line,
        user_name,
        company,
        parent_pid,
        integrity_level,
        signer,
        image_hash,
        operation,
        result,
        path,
        detail,
        proto,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        direction,
        source_pml_path,
    )


def write_procmon_rows(conn: sqlite3.Connection, rows: List[Tuple[object, ...]]) -> None:
    conn.executemany(
        """
        INSERT OR IGNORE INTO procmon_events (
          event_id, ts_us, pid, tid, process_name, process_path, command_line, user_name, company, parent_pid,
          integrity_level, signer, image_hash, operation, result, path, detail,
          proto, local_ip, local_port, remote_ip, remote_port, direction, source_file
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )


def extract_record(elem: ET.Element) -> Dict[str, str]:
    record: Dict[str, str] = {}
    for child in list(elem):
        key = normalize_key(child.tag)
        record[key] = (child.text or "").strip()
    return record


def normalize_key(value: str) -> str:
    return "".join(char for char in value.strip().lower() if char.isalnum() or char == "_")


def value_of(record: Dict[str, str], key: str) -> Optional[str]:
    options = {
        key,
        key.replace(" ", ""),
        key.replace("_", ""),
    }
    for option in options:
        normalized = normalize_key(option)
        if normalized in record and record[normalized]:
            return record[normalized]
    return None


def value_any(record: Dict[str, str], keys: List[str]) -> Optional[str]:
    for key in keys:
        value = value_of(record, key)
        if value:
            return value
    return None


def is_network_record(record: Dict[str, str]) -> bool:
    operation = (value_of(record, "operation") or "").lower()
    category = (value_of(record, "category") or "").lower()
    path_value = (value_of(record, "path") or "").lower()

    if "network" in category:
        return True
    if "tcp" in path_value or "udp" in path_value:
        return True
    return any(keyword in operation for keyword in NETWORK_OPERATION_KEYWORDS)


def extract_timestamp(record: Dict[str, str], base_date: dt.date) -> Optional[int]:
    for candidate in (
        value_of(record, "timeofday"),
        value_of(record, "time"),
        value_of(record, "timestamp"),
        value_of(record, "dateandtime"),
        value_of(record, "utc"),
    ):
        if not candidate:
            continue
        parsed = parse_procmon_timestamp(candidate, base_date)
        if parsed is not None:
            return parsed

        numeric = parse_int(candidate)
        if numeric is None:
            continue
        if numeric > 10_000_000_000_000:
            return numeric
        if numeric > 10_000_000_000:
            return numeric * 1000
        if numeric > 1_000_000_000:
            return numeric * 1_000_000
    return None


def operation_to_proto(operation: Optional[str]) -> str:
    op = (operation or "").upper()
    if "UDP" in op:
        return "UDP"
    if "TCP" in op:
        return "TCP"
    return "TCP"


def extract_endpoints(
    operation: Optional[str], path: Optional[str], detail: Optional[str]
) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[int], str]:
    text = " ".join(filter(None, [path, detail]))
    endpoints = parse_endpoints(text)
    direction = infer_direction(operation)

    if not endpoints:
        return None, None, None, None, direction

    if len(endpoints) == 1:
        ip, port = endpoints[0]
        return None, None, ip, port, direction

    left = endpoints[0]
    right = endpoints[1]
    left_private = is_private_ip(left[0])
    right_private = is_private_ip(right[0])

    if left_private and not right_private:
        local_ip, local_port = left
        remote_ip, remote_port = right
    elif right_private and not left_private:
        local_ip, local_port = right
        remote_ip, remote_port = left
    else:
        local_ip, local_port = left
        remote_ip, remote_port = right

    if direction == "inbound":
        local_ip, remote_ip = remote_ip, local_ip
        local_port, remote_port = remote_port, local_port

    return local_ip, local_port, remote_ip, remote_port, direction


def parse_endpoints(text: str) -> List[Tuple[str, int]]:
    token_results = parse_arrow_endpoints(text)
    if token_results:
        return token_results

    results: List[Tuple[str, int]] = []
    for match in IPV4_ENDPOINT_RE.finditer(text):
        ip = normalize_ip(match.group(1))
        port = parse_int(match.group(2))
        if ip and port is not None:
            results.append((ip, port))
    for match in IPV6_ENDPOINT_RE.finditer(text):
        ip = normalize_ip(match.group(1))
        port = parse_int(match.group(2))
        if ip and port is not None:
            results.append((ip, port))
    deduped: List[Tuple[str, int]] = []
    seen = set()
    for item in results:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def parse_arrow_endpoints(text: str) -> List[Tuple[str, int]]:
    if "->" not in text:
        return []
    parts = [part.strip() for part in text.split("->") if part.strip()]
    if len(parts) < 2:
        return []

    results: List[Tuple[str, int]] = []
    for token in parts[:2]:
        endpoint = parse_endpoint_token(token)
        if endpoint:
            results.append(endpoint)

    deduped: List[Tuple[str, int]] = []
    seen = set()
    for item in results:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def parse_endpoint_token(token: str) -> Optional[Tuple[str, int]]:
    value = token.strip().strip('"').strip()
    if not value or ":" not in value:
        return None

    host_part, port_part = value.rsplit(":", 1)
    host = host_part.strip().strip("[]")
    if not host:
        return None

    port = parse_int(port_part)
    if port is None:
        port = SERVICE_PORTS.get(port_part.strip().lower())
    if port is None:
        return None

    normalized = normalize_ip(host)
    if normalized:
        return normalized, port

    # Keep hostname if IP parsing failed; allows limited matching where hostname appears in both sources.
    return host.lower(), port


def infer_direction(operation: Optional[str]) -> str:
    op = (operation or "").lower()
    if "receive" in op or "recv" in op or "accept" in op:
        return "inbound"
    if "send" in op or "connect" in op:
        return "outbound"
    return "unknown"
