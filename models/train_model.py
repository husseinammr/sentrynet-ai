"""
models/train_model.py — Train, evaluate, and save the Isolation Forest model.
Run this script standalone to produce a serialized model artifact.
"""
import os
import sys
import json
import pickle
import numpy as np
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from services.traffic_simulator import TrafficSimulator
from services.anomaly_detector import AnomalyDetector, extract_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'isolation_forest.pkl')
REPORT_PATH = os.path.join(os.path.dirname(__file__), 'eval_report.json')


def train(n_normal: int = 2000, n_attack: int = 200):
    print("=" * 60)
    print("  AI Network Traffic Analysis — Model Training")
    print("=" * 60)

    sim = TrafficSimulator()
    detector = AnomalyDetector()

    # Generate training data (normal only)
    print(f"\n[1/4] Generating {n_normal} normal traffic samples...")
    normal_data = sim.generate_batch(size=n_normal)
    print(f"      ✓ Done")

    # Train
    print(f"\n[2/4] Training Isolation Forest...")
    detector.train(normal_data)
    print(f"      ✓ Model trained (n_estimators=100, contamination=0.05)")

    # Generate test set: normal + attacks
    print(f"\n[3/4] Generating test set ({n_normal//2} normal + {n_attack} attack samples)...")
    test_normal = sim.generate_batch(size=n_normal // 2)

    # Force attack entries
    sim.attack_mode = True
    attack_entries = []
    for atype in ['ddos', 'port_scan', 'brute_force']:
        sim.attack_type = atype
        sim.attack_source = '185.220.101.45'
        batch = sim.generate_batch(size=n_attack // 3)
        for e in batch:
            if e.get('attack_type'):
                attack_entries.append(e)
    sim.attack_mode = False

    test_set = test_normal + attack_entries
    true_labels = [0] * len(test_normal) + [1] * len(attack_entries)

    print(f"      ✓ Test set: {len(test_normal)} normal, {len(attack_entries)} attacks")

    # Evaluate
    print(f"\n[4/4] Evaluating model...")
    results = detector.analyze(test_set)
    pred_labels = [1 if r['is_anomaly'] else 0 for r in results]

    tp = sum(1 for t, p in zip(true_labels, pred_labels) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(true_labels, pred_labels) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(true_labels, pred_labels) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(true_labels, pred_labels) if t == 1 and p == 0)

    precision = tp / max(tp + fp, 1)
    recall    = tp / max(tp + fn, 1)
    f1        = 2 * precision * recall / max(precision + recall, 1e-9)
    accuracy  = (tp + tn) / max(len(true_labels), 1)

    report = {
        "trained_at": datetime.utcnow().isoformat(),
        "training_samples": n_normal,
        "test_samples": len(test_set),
        "metrics": {
            "accuracy":  round(accuracy, 4),
            "precision": round(precision, 4),
            "recall":    round(recall, 4),
            "f1_score":  round(f1, 4),
        },
        "confusion_matrix": {"TP": tp, "TN": tn, "FP": fp, "FN": fn},
        "model_params": {
            "n_estimators": 100,
            "contamination": 0.05,
            "features": [
                "bytes", "packets", "duration", "dst_port", "src_port",
                "protocol", "conn_state", "bytes_per_sec", "packets_per_sec"
            ]
        }
    }

    # Save model
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump({'model': detector.model, 'scaler': detector.scaler}, f)

    with open(REPORT_PATH, 'w') as f:
        json.dump(report, f, indent=2)

    # Print report
    print(f"\n{'─'*60}")
    print("  EVALUATION REPORT")
    print(f"{'─'*60}")
    print(f"  Accuracy : {accuracy*100:.1f}%")
    print(f"  Precision: {precision*100:.1f}%")
    print(f"  Recall   : {recall*100:.1f}%")
    print(f"  F1 Score : {f1*100:.1f}%")
    print(f"\n  Confusion Matrix:")
    print(f"    TP={tp}  FP={fp}")
    print(f"    FN={fn}  TN={tn}")
    print(f"\n  Model saved → {MODEL_PATH}")
    print(f"  Report saved → {REPORT_PATH}")
    print(f"{'─'*60}\n")

    return report


if __name__ == '__main__':
    train()
