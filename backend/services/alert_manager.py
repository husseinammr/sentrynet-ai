"""
Alert Manager — tracks traffic history, stats, and generates alerts.
"""
from collections import defaultdict, deque
from datetime import datetime
from typing import List, Dict, Optional
import uuid


class AlertManager:
    def __init__(self, history_size: int = 10000):
        self._traffic_history: deque = deque(maxlen=history_size)
        self._alerts: deque = deque(maxlen=500)
        self._ip_stats: dict = defaultdict(lambda: {"bytes": 0, "packets": 0, "conns": 0})
        self._port_stats: dict = defaultdict(int)
        self._protocol_stats: dict = defaultdict(int)
        self._attack_counts: dict = defaultdict(int)
        self.total_alerts = 0
        self.total_traffic = 0
        self._bytes_over_time: deque = deque(maxlen=60)  # 60 buckets
        self._current_bucket_bytes = 0
        self._current_bucket_ts = datetime.utcnow().second

    def process(self, entries: List[Dict]) -> List[Dict]:
        """Process enriched traffic entries; generate alerts for anomalies."""
        new_alerts = []
        now = datetime.utcnow()

        for entry in entries:
            self._traffic_history.append(entry)
            self.total_traffic += 1

            # Update per-IP stats
            src = entry.get("src_ip", "unknown")
            self._ip_stats[src]["bytes"] += entry.get("bytes", 0)
            self._ip_stats[src]["packets"] += entry.get("packets", 0)
            self._ip_stats[src]["conns"] += 1

            # Port and protocol stats
            self._port_stats[entry.get("dst_port", 0)] += 1
            self._protocol_stats[entry.get("proto", "unknown")] += 1

            # Bytes time-series
            self._current_bucket_bytes += entry.get("bytes", 0)
            if now.second != self._current_bucket_ts:
                self._bytes_over_time.append({
                    "ts": now.strftime("%H:%M:%S"),
                    "bytes": self._current_bucket_bytes,
                    "packets": entry.get("packets", 0),
                })
                self._current_bucket_bytes = 0
                self._current_bucket_ts = now.second

            # Generate alert if anomaly detected
            if entry.get("is_anomaly") or entry.get("attack_type"):
                attack_type = entry.get("attack_type", "Unknown")
                self._attack_counts[attack_type] += 1
                alert = {
                    "id": str(uuid.uuid4())[:8],
                    "timestamp": now.isoformat(),
                    "src_ip": src,
                    "dst_ip": entry.get("dst_ip", ""),
                    "dst_port": entry.get("dst_port", 0),
                    "attack_type": attack_type,
                    "severity": entry.get("severity", "medium"),
                    "anomaly_score": entry.get("anomaly_score", 0),
                    "bytes": entry.get("bytes", 0),
                    "packets": entry.get("packets", 0),
                    "geoip": entry.get("geoip"),
                    "message": self._alert_message(entry),
                }
                self._alerts.appendleft(alert)
                new_alerts.append(alert)
                self.total_alerts += 1

        return new_alerts

    def _alert_message(self, entry: Dict) -> str:
        attack = entry.get("attack_type", "Anomaly")
        src = entry.get("src_ip", "?")
        dst_port = entry.get("dst_port", "?")
        score = entry.get("anomaly_score", 0)
        severity = entry.get("severity", "medium").upper()
        return f"[{severity}] {attack} detected from {src} → port {dst_port} (score: {score:.3f})"

    def get_stats(self) -> Dict:
        top_ips = sorted(
            self._ip_stats.items(),
            key=lambda x: x[1]["bytes"],
            reverse=True
        )[:10]

        top_ports = sorted(
            self._port_stats.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        return {
            "total_traffic": self.total_traffic,
            "total_alerts": self.total_alerts,
            "top_ips": [
                {"ip": ip, **stats}
                for ip, stats in top_ips
            ],
            "top_ports": [
                {"port": port, "count": count}
                for port, count in top_ports
            ],
            "protocol_distribution": dict(self._protocol_stats),
            "attack_distribution": dict(self._attack_counts),
            "bytes_over_time": list(self._bytes_over_time)[-30:],
        }

    def get_recent_traffic(self, limit: int = 50) -> List[Dict]:
        return list(self._traffic_history)[-limit:]

    def get_recent_alerts(self, limit: int = 20) -> List[Dict]:
        return list(self._alerts)[:limit]
