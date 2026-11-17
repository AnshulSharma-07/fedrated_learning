"""Generate synthetic CIC-IDS2017-schema CSV benchmark data (clearly marked synthetic)."""
from __future__ import annotations

import argparse
from pathlib import Path
import numpy as np
import pandas as pd


def generate(rows: int = 1200, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    categories = ["Benign", "DoS/DDoS", "PortScan", "BruteForce", "Botnet", "WebAttack"]
    probs = [0.62, 0.14, 0.09, 0.06, 0.05, 0.04]
    records = []
    for _ in range(rows):
        cat = str(rng.choice(categories, p=probs))
        if cat == "Benign":
            dur = max(1200.0, float(rng.normal(245000, 120000)))
            fwd, bwd = max(1, int(rng.normal(9, 4))), max(1, int(rng.normal(8, 4)))
            flen, blen = max(40.0, float(rng.normal(165, 55))), max(40.0, float(rng.normal(420, 140)))
            syn, ack, rst, psh, win = 1, max(1, int(rng.normal(7, 2))), 0, 2, 29200
        elif cat == "DoS/DDoS":
            dur = max(250.0, float(rng.normal(18500, 9500)))
            fwd, bwd = max(12, int(rng.normal(68, 22))), max(0, int(rng.normal(2, 2)))
            flen, blen = max(20.0, float(rng.normal(48, 18))), max(0.0, float(rng.normal(12, 14)))
            syn, ack, rst, psh, win = max(1, int(rng.normal(6, 2))), 1, 2, 0, 512
        elif cat == "PortScan":
            dur = max(80.0, float(rng.normal(1850, 850)))
            fwd, bwd = 2, 1
            flen, blen = 42.0, 28.0
            syn, ack, rst, psh, win = 1, 0, 1, 0, 1024
        elif cat == "BruteForce":
            dur = max(60000.0, float(rng.normal(420000, 95000)))
            fwd, bwd = 24, 22
            flen, blen = 118.0, 145.0
            syn, ack, rst, psh, win = 1, 20, 1, 12, 29200
        elif cat == "Botnet":
            dur = max(150000.0, float(rng.normal(920000, 240000)))
            fwd, bwd = 14, 14
            flen, blen = 78.0, 92.0
            syn, ack, rst, psh, win = 1, 13, 0, 9, 65535
        else:
            dur = max(35000.0, float(rng.normal(310000, 85000)))
            fwd, bwd = 18, 14
            flen, blen = 520.0, 680.0
            syn, ack, rst, psh, win = 1, 16, 0, 7, 64240

        records.append(
            {
                "flow_duration": round(dur, 2),
                "total_fwd_packets": fwd,
                "total_bwd_packets": bwd,
                "fwd_packet_length_mean": round(flen, 2),
                "bwd_packet_length_mean": round(blen, 2),
                "flow_bytes_per_sec": round((fwd * flen + bwd * blen) / (dur / 1e6), 2),
                "flow_packets_per_sec": round((fwd + bwd) / (dur / 1e6), 2),
                "syn_flag_count": syn,
                "ack_flag_count": ack,
                "rst_flag_count": rst,
                "psh_flag_count": psh,
                "iat_mean": round(dur / max(1, fwd + bwd), 2),
                "init_win_bytes_fwd": win,
                "subflow_fwd_bytes": round(fwd * flen, 2),
                "label": cat,
            }
        )
    return pd.DataFrame(records)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=1200)
    parser.add_argument("--out", type=str, default="data/sample/synthetic_cicids2017_sample.csv")
    args = parser.parse_args()
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df = generate(args.rows)
    df.to_csv(out_path, index=False)
    print(f"Generated {len(df)} synthetic flows at {out_path}")
