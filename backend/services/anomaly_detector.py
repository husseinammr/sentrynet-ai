"""
Anomaly Detection Service — Isolation Forest ML model for network traffic.
"""
import numpy as np
from typing import List, Dict, Optional
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings("ignore")

from utils.logger import get_logger

logger = get_logger(__name__)


def extract_features(entry: Dict) -> List[float]:
    """Extract numerical features from a traffic entry."""
    proto_map = {"tcp": 0, "udp": 1, "icmp": 2}
    state_map = {"SF": 0, "S0": 1, "REJ": 2, "RSTO": 3, "OTH": 4}

    return [
        float(entry.get("bytes", 0)),
        float(entry.get("packets", 0)),
        float(entry.get("duration", 0)),
        float(entry.get("dst_port", 0)),
        float(entry.get("src_port", 0)),
        float(proto_map.get(entry.get("proto", "tcp"), 0)),
        float(state_map.get(entry.get("conn_state", "SF"), 0)),
        float(entry.get("bytes", 0) / max(entry.get("duration", 0.001), 0.001)),  # bytes/sec
        float(entry.get("packets", 0) / max(entry.get("duration", 0.001), 0.001)),  # pps
    ]


class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,  # ~5% expected anomalies
            random_state=42,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self._score_threshold = -0.1  # Anomaly boundary

    def train(self, entries: List[Dict]):
        """Train the model on baseline traffic."""
        if not entries:
            return
        X = np.array([extract_features(e) for e in entries])
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True
        logger.info(f"Model trained on {len(entries)} samples.")

    def score_entries(self, entries: List[Dict]) -> List[float]:
        """Return anomaly scores for a list of entries. More negative = more anomalous."""
        if not self.is_trained or not entries:
            return [0.0] * len(entries)
        X = np.array([extract_features(e) for e in entries])
        X_scaled = self.scaler.transform(X)
        return self.model.score_samples(X_scaled).tolist()

    def analyze(self, entries: List[Dict]) -> List[Dict]:
        """Enrich entries with anomaly scores and classification."""
        scores = self.score_entries(entries)
        results = []
        for entry, score in zip(entries, scores):
            enriched = dict(entry)
            enriched["anomaly_score"] = round(score, 4)
            enriched["is_anomaly"] = score < self._score_threshold

            # If the simulator already flagged an attack type, trust it
            # Otherwise use score-based classification
            if not enriched.get("attack_type") and enriched["is_anomaly"]:
                enriched["attack_type"] = self._classify_anomaly(entry, score)

            enriched["severity"] = self._severity(score, enriched.get("attack_type"))
            results.append(enriched)
        return results

    def _classify_anomaly(self, entry: Dict, score: float) -> Optional[str]:
        """Heuristic classification of anomaly type."""
        port = entry.get("dst_port", 0)
        bytes_val = entry.get("bytes", 0)
        packets = entry.get("packets", 0)
        duration = entry.get("duration", 1)
        state = entry.get("conn_state", "")

        # DDoS: high packets, short duration, UDP
        if packets > 200 and duration < 0.5:
            return "DDoS"
        # Port Scan: many short connections to varied ports, rejected
        if state in ("REJ", "S0") and bytes_val < 300 and duration < 0.05:
            return "Port Scan"
        # Brute Force: repeated auth ports, rejected
        if port in (22, 3389, 21, 5900) and state in ("REJ", "RSTO"):
            return "Brute Force"
        # Large data exfiltration
        if bytes_val > 50000 and packets < 50:
            return "Data Exfiltration"
        return "Unknown Anomaly"

    def _severity(self, score: float, attack_type: Optional[str]) -> str:
        severity_map = {
            "DDoS": "critical",
            "Brute Force": "high",
            "Port Scan": "medium",
            "Data Exfiltration": "critical",
        }
        if attack_type and attack_type in severity_map:
            return severity_map[attack_type]
        if score < -0.3:
            return "critical"
        if score < -0.2:
            return "high"
        if score < -0.1:
            return "medium"
        return "low"
