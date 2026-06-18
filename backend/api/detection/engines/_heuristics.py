"""
Post-processing heuristics shared by ML and DL engines.

These rules were carefully tuned in the original
``pids_core/ml_engine.py`` to suppress the most common false positives
(QUIC traffic on UDP/443 misclassified as Infiltration, normal UDP
discovery protocols flagged as Bot, etc.). They run **after** the raw
two-stage classifier output and before the engine returns its label.

The DL engine applies the same rules unless ``settings.DL_RAW_MODE`` is
True (used for fair side-by-side comparison with ML).
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

# Common normal UDP ports (DNS, NTP, DHCP, QUIC, etc.). UDP traffic on
# these ports is usually benign, so we apply a stiffer threshold.
NORMAL_UDP_PORTS = frozenset({
    53,                  # DNS
    67, 68,              # DHCP
    123,                 # NTP
    137, 138, 139,       # NetBIOS
    443,                 # QUIC / HTTP3
    500,                 # IKE / IPSec
    1900,                # SSDP / UPnP
    3478, 3479,          # STUN / TURN (WebRTC)
    5353,                # mDNS
    5355,                # LLMNR
    8080, 8443,          # Common alt-web
})

# Attack categories that historically caused false positives on benign
# UDP traffic. We require extra confidence before reporting these.
SUSPICIOUS_ATTACK_TYPES = frozenset({
    "Infiltration",
    "Infilteration",   # spelling used in CIC-IDS-2018 — both forms tolerated
    "Bot",
    "Portscan",
    "PortScan",
})


# Default knobs. Engines may pass overrides if they want stricter / looser
# behaviour, but we keep the defaults aligned with the legacy MLEngine.
DEFAULT_STAGE1_THRESHOLD: float = 0.7
DEFAULT_STAGE2_MIN_CONFIDENCE: float = 0.85
DEFAULT_UDP_THRESHOLD_BOOST: float = 0.10


def stage1_threshold(
    protocol: str,
    dst_port: int,
    base: float = DEFAULT_STAGE1_THRESHOLD,
    udp_boost: float = DEFAULT_UDP_THRESHOLD_BOOST,
) -> float:
    """
    Return the stage-1 P(Attack) cutoff for a given flow.

    UDP gets a small boost; UDP on a known-normal port gets an extra
    boost on top so QUIC / DNS / NTP almost never trip stage 1.
    """
    threshold = base
    if protocol == "UDP":
        threshold += udp_boost
        if dst_port in NORMAL_UDP_PORTS:
            threshold += 0.15
    return threshold


def stage2_min_confidence(
    protocol: str,
    base: float = DEFAULT_STAGE2_MIN_CONFIDENCE,
) -> float:
    """Higher minimum confidence required for UDP traffic."""
    return base + (0.05 if protocol == "UDP" else 0.0)


def post_process_attack_label(
    attack_type: str,
    confidence: float,
    protocol: str,
    dst_port: int,
    anomaly_probability: float,
) -> Tuple[str, float, str]:
    """
    Apply the legacy false-positive suppression rules to a stage-2 result.

    The caller has already determined that stage 1 fired (anomaly) and
    that stage 2 produced ``(attack_type, confidence)``. This function
    decides whether to:

    * accept it as ``Attack``,
    * downgrade to ``Suspicious``,
    * or override back to ``Normal`` (for high-recall classes on
      well-known benign UDP ports).

    Parameters
    ----------
    attack_type
        Stage-2 predicted class name.
    confidence
        Stage-2 max softmax / proba value (0..1).
    protocol
        ``"TCP"`` / ``"UDP"`` / other.
    dst_port
        Destination port from the flow features.
    anomaly_probability
        Stage-1 P(Attack), used only to compute a sensible "Normal"
        confidence when we override.

    Returns
    -------
    tuple
        ``(label, confidence, status)`` ready to be returned by an engine.
    """
    min_conf = stage2_min_confidence(protocol)

    # Catch-all low-confidence downgrade (applies to every attack type).
    if confidence < min_conf:
        return attack_type, confidence, "Suspicious"

    # Per-class fine-grained rules for the historically noisy classes.
    if attack_type in SUSPICIOUS_ATTACK_TYPES:
        if attack_type in ("Infiltration", "Infilteration"):
            # UDP on port 443 = QUIC/HTTP3 — never an Infiltration attack.
            if protocol == "UDP" and dst_port == 443:
                return "Normal", 1 - anomaly_probability, "Normal"
            # Any normal UDP port: override even with high confidence.
            if protocol == "UDP" and dst_port in NORMAL_UDP_PORTS:
                return "Normal", 1 - anomaly_probability, "Normal"
            # Otherwise demand near-perfect confidence.
            if confidence < 0.99:
                return "Normal", 1 - anomaly_probability, "Normal"
        else:
            # Bot / Portscan: require >= 0.92, otherwise Suspicious.
            if confidence < 0.92:
                return attack_type, confidence, "Suspicious"
            # Even with high confidence, normal UDP ports trump it.
            if protocol == "UDP" and dst_port in NORMAL_UDP_PORTS:
                return "Normal", 1 - confidence, "Normal"

    return attack_type, confidence, "Attack"


def get_dst_port(features: Dict[str, Any]) -> int:
    """
    Pull ``Dst Port`` from a feature dict, returning 0 if missing/invalid.
    """
    try:
        return int(features.get("Dst Port", 0) or 0)
    except (TypeError, ValueError):
        return 0
