from __future__ import annotations

from typing import Any, Dict


def adapt_zeek_or_cicflow_record(raw_flow: Dict[str, Any]) -> Dict[str, float]:
    """Maps external flow-exporter JSON fields (Zeek conn.log / CICFlowMeter) into canonical 14-feature vector."""
    return {
        "flow_duration": float(raw_flow.get("flow_duration", raw_flow.get("duration", 0.0))),
        "total_fwd_packets": float(raw_flow.get("total_fwd_packets", raw_flow.get("orig_pkts", 1.0))),
        "total_bwd_packets": float(raw_flow.get("total_bwd_packets", raw_flow.get("resp_pkts", 0.0))),
        "fwd_packet_length_mean": float(raw_flow.get("fwd_packet_length_mean", 64.0)),
        "bwd_packet_length_mean": float(raw_flow.get("bwd_packet_length_mean", 64.0)),
        "flow_bytes_per_sec": float(raw_flow.get("flow_bytes_per_sec", 0.0)),
        "flow_packets_per_sec": float(raw_flow.get("flow_packets_per_sec", 0.0)),
        "syn_flag_count": float(raw_flow.get("syn_flag_count", 0.0)),
        "ack_flag_count": float(raw_flow.get("ack_flag_count", 0.0)),
        "rst_flag_count": float(raw_flow.get("rst_flag_count", 0.0)),
        "psh_flag_count": float(raw_flow.get("psh_flag_count", 0.0)),
        "iat_mean": float(raw_flow.get("iat_mean", 0.0)),
        "init_win_bytes_fwd": float(raw_flow.get("init_win_bytes_fwd", 8192.0)),
        "subflow_fwd_bytes": float(raw_flow.get("subflow_fwd_bytes", raw_flow.get("orig_ip_bytes", 0.0))),
    }


def classify_alert_severity(predicted_label: str, confidence: float) -> str:
    if predicted_label == "Benign":
        return "low"
    if predicted_label in ("DoS/DDoS", "Botnet") and confidence >= 0.85:
        return "critical"
    if predicted_label in ("DoS/DDoS", "Botnet") or confidence >= 0.85:
        return "high"
    return "medium"
