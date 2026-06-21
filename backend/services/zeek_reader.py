"""
services/zeek_reader.py
المرحلة 4 — قراءة Zeek logs حقيقية
Tails live Zeek conn.log files and parses entries in real-time.
Falls back to simulator if Zeek not available.
"""
import os
import time
import asyncio
from typing import AsyncGenerator, Optional, List, Dict
from utils.logger import get_logger

logger = get_logger(__name__)

# Default Zeek log paths
ZEEK_LOG_PATHS = [
    "/opt/zeek/logs/current/conn.log",
    "/usr/local/zeek/logs/current/conn.log",
    "/var/log/zeek/current/conn.log",
    "/nsm/zeek/logs/current/conn.log",
]

# Zeek conn.log field order (default policy)
ZEEK_FIELDS = [
    "ts", "uid", "src_ip", "src_port", "dst_ip", "dst_port",
    "proto", "service", "duration", "bytes_orig", "bytes_resp",
    "conn_state", "local_orig", "local_resp", "missed_bytes",
    "history", "pkts_orig", "pkts_resp", "tunnel_parents",
]

SERVICE_MAP = {
    "http": 80, "https": 443, "ssh": 22, "ftp": 21,
    "smtp": 25, "dns": 53, "rdp": 3389, "mysql": 3306,
}


def _safe_float(val: str, default: float = 0.0) -> float:
    try:
        return float(val) if val != "-" else default
    except (ValueError, TypeError):
        return default

def _safe_int(val: str, default: int = 0) -> int:
    try:
        return int(val) if val != "-" else default
    except (ValueError, TypeError):
        return default


def parse_zeek_line(line: str) -> Optional[Dict]:
    """Parse a single Zeek conn.log TSV line into a traffic entry dict."""
    if not line or line.startswith("#"):
        return None
    parts = line.strip().split("\t")
    if len(parts) < 12:
        return None
    try:
        entry = {
            "ts":          parts[0],
            "uid":         parts[1] if len(parts) > 1 else "",
            "src_ip":      parts[2],
            "src_port":    _safe_int(parts[3]),
            "dst_ip":      parts[4],
            "dst_port":    _safe_int(parts[5]),
            "proto":       parts[6].lower() if parts[6] != "-" else "tcp",
            "service":     parts[7] if parts[7] != "-" else "",
            "duration":    _safe_float(parts[8]),
            "bytes":       _safe_int(parts[9]) + _safe_int(parts[10]),
            "conn_state":  parts[11] if len(parts) > 11 else "OTH",
            "packets":     _safe_int(parts[16]) + _safe_int(parts[17]) if len(parts) > 17 else 1,
            "attack_type": None,
            "is_anomaly":  False,
            "severity":    "low",
            "anomaly_score": 0.0,
        }
        return entry
    except Exception as e:
        logger.debug(f"Failed to parse Zeek line: {e}")
        return None


class ZeekLogReader:
    """
    Reads live Zeek conn.log by tailing the file.
    If Zeek is not installed, falls back to the traffic simulator.
    """

    def __init__(self, log_path: Optional[str] = None, batch_size: int = 20):
        self.log_path = log_path or self._detect_zeek_log()
        self.batch_size = batch_size
        self.available = self.log_path is not None and os.path.exists(self.log_path)
        self._file = None
        self._position = 0

        if self.available:
            logger.info(f"✓ Zeek log found: {self.log_path}")
        else:
            logger.warning("Zeek log not found — using traffic simulator as fallback.")

    def _detect_zeek_log(self) -> Optional[str]:
        for path in ZEEK_LOG_PATHS:
            if os.path.exists(path):
                return path
        return None

    def _open(self):
        if self._file is None:
            self._file = open(self.log_path, "r")
            # Seek to end to only read new entries
            self._file.seek(0, 2)
            self._position = self._file.tell()

    def read_batch(self) -> List[Dict]:
        """Read next batch of new lines from the log file."""
        if not self.available:
            return []
        try:
            self._open()
            lines = []
            while len(lines) < self.batch_size:
                line = self._file.readline()
                if not line:
                    break
                entry = parse_zeek_line(line)
                if entry:
                    lines.append(entry)
            return lines
        except Exception as e:
            logger.error(f"Zeek read error: {e}")
            self._file = None
            return []

    async def stream(self, interval: float = 1.0) -> AsyncGenerator[List[Dict], None]:
        """Async generator: yields batches of parsed Zeek entries."""
        if not self.available:
            logger.info("Zeek unavailable — yielding empty batches (simulator will handle).")
            while True:
                yield []
                await asyncio.sleep(interval)

        while True:
            batch = self.read_batch()
            yield batch
            await asyncio.sleep(interval)

    def close(self):
        if self._file:
            self._file.close()
            self._file = None


# ─── Convenience: parse a historical Zeek file ───────
def parse_zeek_file(path: str, limit: int = 10000) -> List[Dict]:
    """Parse an existing Zeek conn.log file (not live) for batch ML training."""
    entries = []
    try:
        with open(path, "r") as f:
            for line in f:
                if len(entries) >= limit:
                    break
                entry = parse_zeek_line(line)
                if entry:
                    entries.append(entry)
        logger.info(f"Parsed {len(entries)} entries from {path}")
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
    return entries
