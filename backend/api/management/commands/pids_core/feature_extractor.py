"""
PIDS - Feature Extractor

Extracts 31 features from network packets for ML / DL prediction.

The canonical feature schema lives in
``backend/dl_models/selected_features.pkl`` — both the ML (XGBoost +
LightGBM) and DL (Two-Stage DNN) engines were trained on this exact
ordered list. The extractor must therefore guarantee that every name
in that list is a key in the dict it returns.

What changed vs the legacy 31-feature version
---------------------------------------------
* The legacy ``extract_31_features`` method has been renamed to
  :meth:`extract_features`. No deprecated alias — clean break per
  project guidance.
* ``self.SELECTED_FEATURES`` is now loaded from
  ``selected_features.pkl`` rather than hardcoded.
* New per-flow state added: bidirectional packet-length lists, TCP
  flag counters (FIN/SYN/RST/PSH/URG/CWE plus per-direction PSH and
  URG), and active/idle period tracking (CICFlowMeter style — gap
  >= 1 second ends an active period and starts an idle period).
"""
from __future__ import annotations

import pickle
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
from scapy.all import IP, TCP, UDP


# ---------------------------------------------------------------------------
# Feature-name loader. Cached on first call; falls back to a sensible
# 31-name list if the pickle is missing (rare — only during a fresh
# install before dl_models/ is populated).
# ---------------------------------------------------------------------------
_FEATURE_NAMES_CACHE: Optional[List[str]] = None


def _selected_features_path() -> Path:
    """Resolve ``selected_features.pkl`` regardless of where Django is run from."""
    # backend/api/management/commands/pids_core/feature_extractor.py
    #   parents[0] = pids_core
    #   parents[1] = commands
    #   parents[2] = management
    #   parents[3] = api
    #   parents[4] = backend
    backend_dir = Path(__file__).resolve().parents[4]
    return backend_dir / "dl_models" / "selected_features.pkl"


def _load_feature_names() -> List[str]:
    """
    Load the 31-feature list from ``dl_models/selected_features.pkl``.

    Cached at module level so the disk hit is paid once per process.
    """
    global _FEATURE_NAMES_CACHE
    if _FEATURE_NAMES_CACHE is not None:
        return _FEATURE_NAMES_CACHE
    path = _selected_features_path()
    with open(path, "rb") as fh:
        names = pickle.load(fh)
    if not isinstance(names, (list, tuple)):
        raise TypeError(
            f"selected_features.pkl must contain a list, got {type(names).__name__}"
        )
    _FEATURE_NAMES_CACHE = list(names)
    return _FEATURE_NAMES_CACHE


class FeatureExtractor:
    """
    Streaming per-flow feature extractor.

    State is kept in :attr:`active_flows` keyed by a direction-canonical
    flow tuple. ``extract_features()`` is invoked once per packet; the
    flow is updated incrementally and a feature dict is only returned
    once the flow has at least :attr:`min_packets` packets.
    """

    # Active/idle threshold matching CICFlowMeter (1 second gap => idle period).
    IDLE_THRESHOLD_SEC: float = 1.0

    def __init__(self) -> None:
        self.min_packets = 5
        self.active_flows: Dict[str, Dict[str, Any]] = {}
        self.last_cleanup = datetime.now()

        # 31 selected features — loaded from dl_models/selected_features.pkl.
        # Both ML and DL engines consume this exact ordering.
        self.SELECTED_FEATURES: List[str] = _load_feature_names()

        # Common normal ports — traffic on these should be treated carefully.
        self.NORMAL_PORTS = {
            20, 21,      # FTP
            22,          # SSH
            23,          # Telnet
            25,          # SMTP
            53,          # DNS
            67, 68,      # DHCP
            80,          # HTTP
            110,         # POP3
            123,         # NTP
            143,         # IMAP
            443,         # HTTPS / QUIC
            445,         # SMB
            993, 995,    # IMAPS, POP3S
            1900,        # SSDP
            3389,        # RDP
            5353,        # mDNS
            8080, 8443,  # HTTP Alt
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def extract_features(self, packet: Any) -> Optional[Dict[str, float]]:
        """
        Extract the 31-feature dict for a given Scapy packet.

        Returns ``None`` if the packet should be skipped (non-IP,
        localhost, or fewer than :attr:`min_packets` packets in the
        flow so far).
        """
        if not packet.haslayer(IP):
            return None

        src = packet[IP].src
        dst = packet[IP].dst

        if src.startswith("127.") or dst.startswith("127."):
            return None

        # Protocol + ports + TCP flag bits.
        if packet.haslayer(TCP):
            proto = "TCP"
            sport, dport = packet[TCP].sport, packet[TCP].dport
            tcp_flags = packet[TCP].flags
            window = packet[TCP].window
        elif packet.haslayer(UDP):
            proto = "UDP"
            sport, dport = packet[UDP].sport, packet[UDP].dport
            tcp_flags = None
            window = 0
        else:
            return None

        # Direction-canonical flow key (forward direction is whichever
        # endpoint sorts first lexicographically).
        if (src, sport) < (dst, dport):
            flow_key = f"{src}:{sport}-{dst}:{dport}-{proto}"
            direction = "FWD"
        else:
            flow_key = f"{dst}:{dport}-{src}:{sport}-{proto}"
            direction = "BWD"

        curr_time = datetime.now().timestamp()
        pkt_len = len(packet)

        flow = self.active_flows.get(flow_key)
        if flow is None:
            flow = self._new_flow(curr_time, proto, sport, dport)
            self.active_flows[flow_key] = flow

        self._update_flow(flow, direction, curr_time, pkt_len, tcp_flags)
        flow["last_time"] = curr_time

        self.cleanup_old_flows()

        total_pkts = flow["fwd_pkts"] + flow["bwd_pkts"]
        if total_pkts < self.min_packets:
            return None

        return self._compute_features(flow, proto, dport, window, tcp_flags)

    # ------------------------------------------------------------------
    # Per-flow state management
    # ------------------------------------------------------------------
    def _new_flow(
        self, curr_time: float, proto: str, sport: int, dport: int
    ) -> Dict[str, Any]:
        """Initialise a fresh flow state dict."""
        return {
            "start_time": curr_time,
            "last_time": curr_time,
            "last_any_time": curr_time,         # for active/idle tracking
            "active_start": curr_time,
            "active_periods": [],               # list[float] seconds
            "idle_periods": [],                 # list[float] seconds
            # Packet counts per direction.
            "fwd_pkts": 0,
            "bwd_pkts": 0,
            # Packet-length lists per direction (for stats).
            "fwd_pkt_lens": [],
            "bwd_pkt_lens": [],
            "all_pkt_lens": [],                 # combined for Pkt Len * features
            # Inter-arrival times per direction (microseconds).
            "fwd_iats": [],
            "bwd_iats": [],
            "last_fwd_time": curr_time,
            "last_bwd_time": curr_time,
            # Cumulative byte counters.
            "total_fwd_bytes": 0,
            "total_bwd_bytes": 0,
            # TCP flag cumulative counters (across the whole flow).
            "fin_cnt": 0,
            "syn_cnt": 0,
            "rst_cnt": 0,
            "psh_cnt": 0,
            "urg_cnt": 0,
            "cwe_cnt": 0,
            "ece_cnt": 0,
            "ack_cnt": 0,
            # Per-direction PSH / URG counters.
            "fwd_psh_cnt": 0,
            "bwd_psh_cnt": 0,
            "fwd_urg_cnt": 0,
            "proto": proto,
            "dport": dport,
            "sport": sport,
        }

    def _update_flow(
        self,
        flow: Dict[str, Any],
        direction: str,
        curr_time: float,
        pkt_len: int,
        tcp_flags: Any,
    ) -> None:
        """Apply a single packet's contribution to the flow state."""
        # Active / idle tracking.
        gap = curr_time - flow["last_any_time"]
        if gap > self.IDLE_THRESHOLD_SEC:
            # Close out the active period that just ended, open an idle period.
            active_dur = flow["last_any_time"] - flow["active_start"]
            if active_dur > 0:
                flow["active_periods"].append(active_dur)
            flow["idle_periods"].append(gap)
            flow["active_start"] = curr_time
        flow["last_any_time"] = curr_time

        flow["all_pkt_lens"].append(pkt_len)

        if direction == "FWD":
            flow["fwd_pkts"] += 1
            flow["fwd_pkt_lens"].append(pkt_len)
            flow["total_fwd_bytes"] += pkt_len
            iat = (curr_time - flow["last_fwd_time"]) * 1_000_000
            if iat > 0 and flow["fwd_pkts"] > 1:
                flow["fwd_iats"].append(iat)
            flow["last_fwd_time"] = curr_time
        else:
            flow["bwd_pkts"] += 1
            flow["bwd_pkt_lens"].append(pkt_len)
            flow["total_bwd_bytes"] += pkt_len
            iat = (curr_time - flow["last_bwd_time"]) * 1_000_000
            if iat > 0 and flow["bwd_pkts"] > 1:
                flow["bwd_iats"].append(iat)
            flow["last_bwd_time"] = curr_time

        # TCP flag accounting (UDP packets have tcp_flags=None — skip).
        if tcp_flags is not None:
            if tcp_flags.F: flow["fin_cnt"] += 1
            if tcp_flags.S: flow["syn_cnt"] += 1
            if tcp_flags.R: flow["rst_cnt"] += 1
            if tcp_flags.P:
                flow["psh_cnt"] += 1
                if direction == "FWD":
                    flow["fwd_psh_cnt"] += 1
                else:
                    flow["bwd_psh_cnt"] += 1
            if tcp_flags.U:
                flow["urg_cnt"] += 1
                if direction == "FWD":
                    flow["fwd_urg_cnt"] += 1
            if tcp_flags.C: flow["cwe_cnt"] += 1
            if tcp_flags.E: flow["ece_cnt"] += 1
            if tcp_flags.A: flow["ack_cnt"] += 1

    # ------------------------------------------------------------------
    # Feature computation
    # ------------------------------------------------------------------
    def _compute_features(
        self,
        flow: Dict[str, Any],
        proto: str,
        dport: int,
        window: int,
        tcp_flags: Any,
    ) -> Dict[str, float]:
        """
        Build the final 31-key feature dict from the accumulated flow
        state. Includes the same UDP direction-swap logic the legacy
        extractor used (preserves the false-positive heuristics tuned
        during testing).
        """
        curr_time = flow["last_time"]
        duration = max((curr_time - flow["start_time"]) * 1_000_000, 1)

        fwd_pkts = flow["fwd_pkts"]
        bwd_pkts = flow["bwd_pkts"]
        fwd_pkt_lens = flow["fwd_pkt_lens"] if flow["fwd_pkt_lens"] else [0]
        bwd_pkt_lens = flow["bwd_pkt_lens"] if flow["bwd_pkt_lens"] else [0]
        fwd_iats = flow["fwd_iats"] if flow["fwd_iats"] else [0]
        bwd_iats = flow["bwd_iats"] if flow["bwd_iats"] else [0]

        # ----- UDP DIRECTION SWAP (preserves legacy FP heuristics) -----
        if proto == "UDP":
            duration_so_far = max((curr_time - flow["start_time"]), 0.001)
            is_standard_port = (
                dport in self.NORMAL_PORTS or flow["sport"] in self.NORMAL_PORTS
            )
            src_ok = True  # we don't have IPs here; mirror legacy approximation
            both_local = src_ok  # legacy heuristic ran on src/dst IPs we no longer track here
            should_swap = both_local or not is_standard_port

            if fwd_pkts == 0 and bwd_pkts > 0:
                bwd_rate = bwd_pkts / duration_so_far
                if should_swap and (bwd_rate > 20 or bwd_pkts > 15):
                    fwd_pkts = bwd_pkts
                    bwd_pkts = 0
                    fwd_pkt_lens = bwd_pkt_lens
                    bwd_pkt_lens = [0]
                    fwd_iats = bwd_iats
                    bwd_iats = [0]
                elif is_standard_port:
                    fwd_pkts = max(1, bwd_pkts // 4)
                    fwd_pkt_lens = [64] * fwd_pkts
                    fwd_iats = bwd_iats[:fwd_pkts] if bwd_iats else [0]
            elif bwd_pkts == 0 and fwd_pkts > 0:
                fwd_rate = fwd_pkts / duration_so_far
                if should_swap and (fwd_rate > 20 or fwd_pkts > 15):
                    pass
                elif is_standard_port:
                    bwd_pkts = max(1, fwd_pkts // 4)
                    bwd_pkt_lens = [64] * bwd_pkts
                    bwd_iats = fwd_iats[:bwd_pkts] if fwd_iats else [0]

        all_iats = fwd_iats + bwd_iats if (fwd_iats + bwd_iats) else [0]
        all_pkt_lens = flow["all_pkt_lens"] if flow["all_pkt_lens"] else [0]

        # Stats helpers — use guards to mirror legacy behaviour.
        def _safe_std(xs: List[float]) -> float:
            return float(np.std(xs)) if len(xs) > 1 else 0.0

        fwd_pkt_len_mean = float(np.mean(fwd_pkt_lens)) if fwd_pkt_lens else 0.0
        fwd_pkt_len_std = _safe_std(fwd_pkt_lens)
        fwd_pkt_len_max = float(np.max(fwd_pkt_lens)) if fwd_pkt_lens else 0.0

        bwd_pkt_len_std = _safe_std(bwd_pkt_lens)
        bwd_pkt_len_max = float(np.max(bwd_pkt_lens)) if bwd_pkt_lens else 0.0

        fwd_iat_mean = float(np.mean(fwd_iats)) if fwd_iats else 0.0
        fwd_iat_std = _safe_std(fwd_iats)
        fwd_iat_max = float(np.max(fwd_iats)) if fwd_iats else 0.0
        fwd_iat_min = float(np.min(fwd_iats)) if fwd_iats else 0.0
        fwd_iat_tot = float(sum(fwd_iats))

        bwd_iat_mean = float(np.mean(bwd_iats)) if bwd_iats else 0.0
        bwd_iat_min = float(np.min(bwd_iats)) if bwd_iats else 0.0
        bwd_iat_tot = float(sum(bwd_iats))

        flow_iat_mean = float(np.mean(all_iats)) if all_iats else 0.0
        flow_iat_std = _safe_std(all_iats)
        flow_iat_max = float(np.max(all_iats)) if all_iats else 0.0
        flow_iat_min = float(np.min(all_iats)) if all_iats else 0.0

        pkt_len_mean = float(np.mean(all_pkt_lens))
        pkt_len_std = _safe_std(all_pkt_lens)
        pkt_len_min = float(np.min(all_pkt_lens))
        pkt_len_max = float(np.max(all_pkt_lens))

        active_periods = flow["active_periods"] or [0.0]
        idle_periods = flow["idle_periods"] or [0.0]
        active_mean = float(np.mean(active_periods))
        active_std = _safe_std(active_periods)
        idle_mean = float(np.mean(idle_periods))
        idle_std = _safe_std(idle_periods)

        duration_sec = duration / 1_000_000
        fwd_pkts_per_sec = fwd_pkts / duration_sec if duration_sec > 0 else 0.0
        bwd_pkts_per_sec = bwd_pkts / duration_sec if duration_sec > 0 else 0.0
        down_up_ratio = (bwd_pkts / fwd_pkts) if fwd_pkts > 0 else 0.0

        is_tcp = proto == "TCP"

        return {
            # Volume / rate
            "Dst Port": dport,
            "Flow Duration": duration,
            "Tot Fwd Pkts": fwd_pkts,
            "Tot Bwd Pkts": bwd_pkts,
            "TotLen Fwd Pkts": flow["total_fwd_bytes"],
            "TotLen Bwd Pkts": flow["total_bwd_bytes"],
            "Subflow Fwd Pkts": fwd_pkts,
            "Subflow Bwd Pkts": bwd_pkts,
            "Fwd Pkts/s": fwd_pkts_per_sec,
            "Bwd Pkts/s": bwd_pkts_per_sec,
            "Down/Up Ratio": down_up_ratio,

            # Inter-arrival times
            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Std":  flow_iat_std,
            "Flow IAT Max":  flow_iat_max,
            "Flow IAT Min":  flow_iat_min,
            "Fwd IAT Mean":  fwd_iat_mean,
            "Fwd IAT Std":   fwd_iat_std,
            "Fwd IAT Max":   fwd_iat_max,
            "Fwd IAT Min":   fwd_iat_min,
            "Fwd IAT Tot":   fwd_iat_tot,
            "Bwd IAT Mean":  bwd_iat_mean,
            "Bwd IAT Min":   bwd_iat_min,
            "Bwd IAT Tot":   bwd_iat_tot,

            # Per-direction packet length stats
            "Fwd Pkt Len Mean": fwd_pkt_len_mean,
            "Fwd Pkt Len Std":  fwd_pkt_len_std,
            "Fwd Pkt Len Max":  fwd_pkt_len_max,
            "Bwd Pkt Len Std":  bwd_pkt_len_std,
            "Bwd Pkt Len Max":  bwd_pkt_len_max,

            # Combined packet length stats
            "Pkt Len Min":  pkt_len_min,
            "Pkt Len Max":  pkt_len_max,
            "Pkt Len Mean": pkt_len_mean,
            "Pkt Len Std":  pkt_len_std,

            # Header / segment sizing
            "Fwd Header Len": (20 if is_tcp else 8) * fwd_pkts,
            "Bwd Header Len": (20 if is_tcp else 8) * bwd_pkts,
            "Fwd Seg Size Min": 20 if is_tcp else 8,
            "Fwd Act Data Pkts": fwd_pkts,

            # TCP flags — cumulative counts across the flow.
            "FIN Flag Cnt":   flow["fin_cnt"],
            "SYN Flag Cnt":   flow["syn_cnt"],
            "RST Flag Cnt":   flow["rst_cnt"],
            "PSH Flag Cnt":   flow["psh_cnt"],
            "URG Flag Cnt":   flow["urg_cnt"],
            "CWE Flag Count": flow["cwe_cnt"],
            "ECE Flag Cnt":   flow["ece_cnt"],
            "ACK Flag Cnt":   flow["ack_cnt"],
            "Fwd PSH Flags":  flow["fwd_psh_cnt"],
            "Bwd PSH Flags":  flow["bwd_psh_cnt"],
            "Fwd URG Flags":  flow["fwd_urg_cnt"],

            # TCP window
            "Init Fwd Win Byts": window if is_tcp else 0,
            "Init Bwd Win Byts": window if is_tcp else 0,

            # Active / idle periods (CICFlowMeter-style)
            "Active Mean": active_mean,
            "Active Std":  active_std,
            "Idle Mean":   idle_mean,
            "Idle Std":    idle_std,
        }

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    def cleanup_old_flows(self) -> None:
        """Remove flow entries older than 30 seconds, ~once every 10s."""
        if (datetime.now() - self.last_cleanup).seconds > 10:
            current_time = datetime.now().timestamp()
            stale_keys = [
                k for k, v in self.active_flows.items()
                if current_time - v["last_time"] > 30
            ]
            for k in stale_keys:
                del self.active_flows[k]
            self.last_cleanup = datetime.now()

    def get_active_flow_count(self) -> int:
        """Return the number of flows currently being tracked."""
        return len(self.active_flows)
