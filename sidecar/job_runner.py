from __future__ import annotations

import argparse
import json
import os
import sqlite3
import traceback
from pathlib import Path
from typing import Dict, List

from common import emit
from correlate import correlate_to_report
from pcap_ingest import ingest_pcap_to_sqlite
from procmon_ingest import ingest_procmon_to_sqlite


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PCAP Analyzer correlation sidecar")
    parser.add_argument("--request", required=True, help="Path to request JSON file")
    return parser.parse_args()


def ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS pcap_sessions (
          session_id TEXT PRIMARY KEY,
          proto TEXT NOT NULL,
          src_ip TEXT NOT NULL,
          src_port INTEGER,
          dst_ip TEXT NOT NULL,
          dst_port INTEGER,
          first_ts_us INTEGER NOT NULL,
          last_ts_us INTEGER NOT NULL,
          packet_count INTEGER NOT NULL,
          byte_count INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS procmon_events (
          event_id TEXT PRIMARY KEY,
          ts_us INTEGER NOT NULL,
          pid INTEGER,
          tid INTEGER,
          process_name TEXT,
          process_path TEXT,
          command_line TEXT,
          user_name TEXT,
          company TEXT,
          parent_pid INTEGER,
          integrity_level TEXT,
          signer TEXT,
          image_hash TEXT,
          operation TEXT,
          result TEXT,
          path TEXT,
          detail TEXT,
          proto TEXT NOT NULL,
          local_ip TEXT,
          local_port INTEGER,
          remote_ip TEXT,
          remote_port INTEGER,
          direction TEXT,
          source_file TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_pcap_time ON pcap_sessions(first_ts_us, last_ts_us);
        CREATE INDEX IF NOT EXISTS idx_procmon_remote ON procmon_events(proto, remote_ip, remote_port, ts_us);
        CREATE INDEX IF NOT EXISTS idx_procmon_pid_time ON procmon_events(pid, ts_us);
        """
    )
    conn.commit()


def run() -> int:
    args = parse_args()
    request_path = Path(args.request)
    if not request_path.exists():
        emit("error", message=f"Brak pliku request: {request_path}")
        return 2

    request = json.loads(request_path.read_text(encoding="utf-8"))
    output_dir = Path(request["outputDir"])
    output_dir.mkdir(parents=True, exist_ok=True)

    db_path = output_dir / "correlation.db"
    report_path = output_dir / "report.json"

    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    ensure_schema(conn)

    warnings: List[str] = []
    parser_mode = "xml_only"
    try:
        emit("progress", stage="prepare", current=0, total=1, message="Inicjalizacja korelacji")

        def pcap_progress(current: int, total: int, message: str) -> None:
            emit("progress", stage="ingest_pcap", current=current, total=total, message=message)

        packet_count = ingest_pcap_to_sqlite(request["pcapFilePath"], conn, pcap_progress)
        emit("progress", stage="ingest_pcap", current=1, total=1, message=f"PCAP gotowy: {packet_count:,} pakietow")

        def procmon_progress(current: int, total: int, message: str) -> None:
            emit("progress", stage="ingest_procmon", current=current, total=total, message=message)

        emit("progress", stage="ingest_procmon", current=0, total=1, message="Start odczytu plikow Procmon...")
        procmon_result = ingest_procmon_to_sqlite(
            procmon_files=request["procmonFilePaths"],
            procmon_executable=request["procmonExecutable"],
            conn=conn,
            output_dir=str(output_dir),
            on_progress=procmon_progress,
        )
        parser_mode = str(procmon_result.get("parser_mode", "xml_only"))
        warnings.extend(list(procmon_result.get("warnings", [])))
        procmon_events_total = int(procmon_result.get("total_events", 0))

        emit(
            "progress",
            stage="ingest_procmon",
            current=1,
            total=1,
            message=f"Procmon gotowy: {procmon_events_total:,} eventow",
        )

        if procmon_events_total <= 0:
            warnings_text = " | ".join(warnings[-4:]) if warnings else "Brak dodatkowych diagnostyk."
            raise RuntimeError(
                "Nie udalo sie wydobyc eventow sieciowych z pliku PML. "
                "Sprawdz czy log Procmon zawiera aktywnosc Network i czy eksport CLI jest wspierany. "
                f"Szczegoly: {warnings_text}"
            )

        def correlate_progress(current: int, total: int, message: str) -> None:
            stage = "align" if "synchronizacji" in message.lower() else "match"
            emit("progress", stage=stage, current=current, total=total, message=message)

        report = correlate_to_report(
            conn=conn,
            analysis_id=request["analysisId"],
            pcap_file_path=request["pcapFilePath"],
            procmon_files=request["procmonFilePaths"],
            parser_mode=parser_mode,
            warnings=warnings,
            options=request.get("options", {}),
            on_progress=correlate_progress,
        )
        report_path.write_text(json.dumps(report, ensure_ascii=True), encoding="utf-8")
        emit("progress", stage="finalize", current=1, total=1, message="Raport korelacji zapisany")
        emit("result", report_path=str(report_path))
        return 0
    except Exception as error:
        details = traceback.format_exc(limit=8)
        emit("error", message=f"{error}\n{details}")
        return 1
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(run())
