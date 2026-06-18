"""
PIDS - Threat Intelligence Service (v3 - Behaviour-First)
Uses behavioural feature analysis FIRST, then port/search as secondary.
DuckDuckGo search + Ollama for enrichment, not primary classification.
"""
import json
import requests
import re
import time
import math
from datetime import datetime
from colorama import Fore, Style
from django.conf import settings


class ThreatIntelligenceService:
    """
    Three-layer analysis:
    1. BEHAVIOURAL PROFILING - Analyse the 31 flow features (primary)
    2. PORT + CONTEXT      - Port reputation + IP context (secondary)
    3. LLM ENRICHMENT      - Ollama + DuckDuckGo (enrichment only)
    """

    def __init__(self):
        self.ollama_host = getattr(settings, 'OLLAMA_HOST', 'http://localhost:11434')
        self.ollama_model = getattr(settings, 'OLLAMA_MODEL', 'llama3.2:1b')
        self.ollama_available = False
        self.last_search_time = 0
        self.min_search_interval = 2.0
        self.cache = {}
        self.cache_duration = 300

        self._check_ollama()
        print(f"{Fore.GREEN}✅ Threat Intelligence Service v3 (Behaviour-First){Style.RESET_ALL}")
        print(f"{Fore.CYAN}   🧠 Behavioural Profiling: Enabled (31 features){Style.RESET_ALL}")
        print(f"{Fore.CYAN}   🔍 DuckDuckGo Search: Enabled{Style.RESET_ALL}")
        print(f"{Fore.CYAN}   🤖 Ollama LLM: {'Enabled' if self.ollama_available else 'Disabled'}{Style.RESET_ALL}")

    @property
    def is_available(self):
        return True

    def _check_ollama(self):
        try:
            response = requests.get(f"{self.ollama_host}/api/tags", timeout=5)
            self.ollama_available = response.status_code == 200
        except Exception:
            self.ollama_available = False

    # =========================================================================
    #  MAIN ENTRY POINT
    # =========================================================================
    def analyze_zero_day(self, traffic_data: dict, features: dict) -> dict:
        try:
            dst_port = features.get('Dst Port', 0) if isinstance(features, dict) else 0
            src_ip = traffic_data.get('src_ip', '')
            dst_ip = traffic_data.get('dst_ip', '')
            protocol = traffic_data.get('protocol', 'TCP')
            skip_cache = traffic_data.get('skip_cache', False)

            # PRIORITY 0: Known safe traffic
            safe_check = self._is_safe_traffic(src_ip, dst_ip, dst_port)
            if safe_check:
                return self._result(False, "Normal", 0.95, safe_check)

            # Check cache (skip on recheck)
            cache_key = f"{dst_port}_{protocol}_{src_ip[:8] if src_ip else 'x'}"
            if not skip_cache:
                cached = self._get_cached(cache_key)
                if cached:
                    return cached

            # ============================================================
            # PRIORITY 1: BEHAVIOURAL FEATURE ANALYSIS (the core fix)
            # Analyse the 31 features to determine attack type by BEHAVIOUR
            # This runs BEFORE port checks to avoid port-based misclassification
            # ============================================================
            behaviour = self._analyse_behaviour(features, protocol)

            if behaviour['is_attack'] and behaviour['confidence'] >= 0.85:
                # Behavioural analysis is confident - use it directly
                print(f"{Fore.RED}   🧠 BEHAVIOUR: {behaviour['attack_type']} "
                      f"({behaviour['confidence']:.0%}) - {behaviour['reason']}{Style.RESET_ALL}")
                result = self._result(True, behaviour['attack_type'],
                                      behaviour['confidence'], behaviour['reason'])
                self._cache_result(cache_key, result)
                return result

            # ============================================================
            # PRIORITY 2: HIGH-RISK PORT CHECK (only for dedicated malware ports)
            # Only for ports that are EXCLUSIVELY malicious (4444, 31337, etc.)
            # NOT for dual-use ports like 8080, 22, 3389
            # ============================================================
            exclusive_malware_ports = {
                4444: ("Metasploit Reverse Shell", 0.95),
                1337: ("Backdoor Trojan", 0.90),
                31337: ("Back Orifice Trojan", 0.95),
            }
            if dst_port in exclusive_malware_ports:
                name, conf = exclusive_malware_ports[dst_port]
                result = self._result(True, name, conf,
                                      f"Exclusively malicious port {dst_port}")
                self._cache_result(cache_key, result)
                return result

            # ============================================================
            # PRIORITY 3: COMBINED ANALYSIS (behaviour + port + search)
            # For uncertain cases, combine all signals
            # ============================================================
            # Get threat intel from search
            search_results = self._search_threat_intel(dst_port, protocol, features)

            # Dual-use ports - behaviour MUST confirm the attack type
            dual_use_ports = {
                8080: "Web Proxy", 22: "SSH", 3389: "RDP", 445: "SMB",
                23: "Telnet", 1433: "MSSQL", 3306: "MySQL", 5555: "ADB",
                6667: "IRC", 9001: "Tor", 2375: "Docker", 27017: "MongoDB",
                6379: "Redis", 80: "HTTP", 443: "HTTPS",
            }

            if dst_port in dual_use_ports:
                # For dual-use ports, behaviour decides the attack TYPE
                # Port only adds context for what SERVICE is targeted
                if behaviour['is_attack']:
                    # Behaviour says attack - use behaviour's type, not port's type
                    attack_type = behaviour['attack_type']
                    conf = behaviour['confidence']
                    reason = f"{behaviour['reason']} (targeting {dual_use_ports[dst_port]} on port {dst_port})"
                    result = self._result(True, attack_type, conf, reason)
                elif behaviour['is_suspicious']:
                    # Uncertain - check search results to tip the balance
                    search_attack = self._classify_from_search(search_results)
                    if search_attack:
                        # But OVERRIDE with behaviour type if behaviour found one
                        final_type = behaviour.get('attack_type', search_attack['type'])
                        if final_type == 'Normal':
                            final_type = search_attack['type']
                        result = self._result(True, final_type,
                                              min(behaviour['confidence'] + 0.1, 0.92),
                                              f"Behavioural anomaly + threat intel match")
                    else:
                        result = self._result(False, "Normal", 0.80,
                                              f"Dual-use port {dst_port}, no strong threat indicators")
                else:
                    result = self._result(False, "Normal", 0.88,
                                          f"Normal traffic on {dual_use_ports[dst_port]}")
            else:
                # Unknown port - rely on behaviour + search
                if behaviour['is_attack']:
                    result = self._result(True, behaviour['attack_type'],
                                          behaviour['confidence'], behaviour['reason'])
                elif behaviour['is_suspicious']:
                    search_attack = self._classify_from_search(search_results)
                    if search_attack:
                        result = self._result(True, search_attack['type'],
                                              search_attack['confidence'],
                                              search_attack['reason'])
                    else:
                        # Try Ollama for enrichment
                        if self.ollama_available:
                            result = self._analyze_with_ollama(traffic_data, features, search_results)
                        else:
                            result = self._result(False, "Normal", 0.75,
                                                  "Insufficient evidence")
                else:
                    result = self._result(False, "Normal", 0.85, "No threat indicators")

            self._cache_result(cache_key, result)
            return result

        except Exception as e:
            print(f"{Fore.RED}Threat Intel Error: {e}{Style.RESET_ALL}")
            return self._result(False, "Normal", 0.50, f"Analysis error: {e}")

    # =========================================================================
    #  BEHAVIOURAL FEATURE ANALYSIS (the core engine)
    # =========================================================================
    def _analyse_behaviour(self, features: dict, protocol: str) -> dict:
        """
        Analyse the 31 flow features to determine attack type by BEHAVIOUR.
        This is the PRIMARY classification method.
        Returns: {is_attack, is_suspicious, attack_type, confidence, reason}
        """
        if not isinstance(features, dict):
            return {'is_attack': False, 'is_suspicious': False,
                    'attack_type': 'Normal', 'confidence': 0.5, 'reason': 'No features'}

        # Extract key behavioural features
        fwd_pkts_s    = features.get('Fwd Pkts/s', 0) or 0
        bwd_pkts_s    = features.get('Bwd Pkts/s', 0) or 0
        fwd_pkt_mean  = features.get('Fwd Pkt Len Mean', 0) or 0
        fwd_pkt_max   = features.get('Fwd Pkt Len Max', 0) or 0
        fwd_pkt_std   = features.get('Fwd Pkt Len Std', 0) or 0
        bwd_pkt_max   = features.get('Bwd Pkt Len Max', 0) or 0
        bwd_pkt_std   = features.get('Bwd Pkt Len Std', 0) or 0
        flow_duration = features.get('Flow Duration', 0) or 0
        flow_iat_mean = features.get('Flow IAT Mean', 0) or 0
        flow_iat_min  = features.get('Flow IAT Min', 0) or 0
        flow_iat_std  = features.get('Flow IAT Std', 0) or 0
        fwd_iat_mean  = features.get('Fwd IAT Mean', 0) or 0
        fwd_iat_std   = features.get('Fwd IAT Std', 0) or 0
        bwd_iat_mean  = features.get('Bwd IAT Mean', 0) or 0
        bwd_iat_tot   = features.get('Bwd IAT Tot', 0) or 0
        subflow_fwd   = features.get('Subflow Fwd Pkts', 0) or 0
        subflow_bwd   = features.get('Subflow Bwd Pkts', 0) or 0
        ack_flag      = features.get('ACK Flag Cnt', 0) or 0
        ece_flag      = features.get('ECE Flag Cnt', 0) or 0
        init_fwd_win  = features.get('Init Fwd Win Byts', 0) or 0
        init_bwd_win  = features.get('Init Bwd Win Byts', 0) or 0
        fwd_header    = features.get('Fwd Header Len', 0) or 0
        bwd_header    = features.get('Bwd Header Len', 0) or 0
        fwd_act_data  = features.get('Fwd Act Data Pkts', 0) or 0
        dst_port      = features.get('Dst Port', 0) or 0

        total_pkts_s = fwd_pkts_s + bwd_pkts_s
        duration_sec = flow_duration / 1_000_000 if flow_duration > 0 else 0

        # ==================================================================
        # PATTERN 0: KNOWN MALICIOUS PORT (checked FIRST)
        # If traffic is on a known attack port, classify by port context
        # This prevents DoS pattern from overriding exfiltration/C2/shell
        # ==================================================================
        exfil_shell_ports = {4444, 4443, 1337, 31337, 5555, 8888, 7777, 1234, 12345}
        c2_malware_ports = {6667, 9001, 2375, 6379, 27017}
        
        if dst_port in exfil_shell_ports and fwd_pkt_mean > 100:
            return {'is_attack': True, 'is_suspicious': False,
                    'attack_type': 'Data Exfiltration',
                    'confidence': 0.90,
                    'reason': f"traffic on known malicious port {dst_port} "
                              f"(Metasploit/reverse shell) with data payload ({fwd_pkt_mean:.0f}B avg)"}
        
        if dst_port in c2_malware_ports and (fwd_pkts_s > 0 or bwd_pkts_s > 0):
            return {'is_attack': True, 'is_suspicious': False,
                    'attack_type': 'Botnet C2 Communication',
                    'confidence': 0.88,
                    'reason': f"traffic on known C2/exploit port {dst_port}"}

        # ==================================================================
        # PATTERN 1a: SLOW DoS  (Slowloris / SlowHTTPTest)
        # Signature: connection held open a LONG time, very LOW packet rate,
        #            TINY (partial-header) packets, web port, and the server
        #            barely replies because the request never completes.
        # This is the OPPOSITE of a flood, so the rate-based PATTERN 1 below
        # can NEVER catch it — it must be checked explicitly here.
        # ==================================================================
        slow_dos_port = dst_port in {80, 443, 8080, 8443}
        if (protocol == 'TCP' and slow_dos_port
                and duration_sec >= 8         # held open (Flow Duration is microseconds)
                and subflow_fwd >= 3          # a trickle of packets, not a one-shot request
                and 0 < total_pkts_s < 8      # low-and-slow, not a flood
                and fwd_pkt_mean < 120        # partial-header sized packets
                and bwd_pkt_max < 200         # server has NOT sent a real HTTP response
                and bwd_pkts_s < 2):          # almost no replies (request never completes)
            return {'is_attack': True, 'is_suspicious': False,
                    'attack_type': "DoS attacks-Slowloris",
                    'confidence': 0.90,
                    'reason': (f"low-and-slow: {duration_sec:.0f}s flow, "
                               f"{total_pkts_s:.1f} pkt/s, {fwd_pkt_mean:.0f}B packets, "
                               f"server barely responding (Slowloris signature)")}

        # ==================================================================
        # PATTERN 1: DoS / DDoS FLOOD
        # Signature: Very high packet rate in ONE direction, unidirectional,
        #            short duration, no ACK (no proper handshake)
        # Check BOTH directions — flood can be fwd OR bwd depending on flow key
        # ==================================================================
        dos_score = 0
        dos_reasons = []

        # Use the HIGHER rate of the two directions as the "attack rate"
        # and the LOWER as the "response rate"
        if fwd_pkts_s >= bwd_pkts_s:
            attack_rate = fwd_pkts_s
            response_rate = bwd_pkts_s
            attack_pkt_mean = fwd_pkt_mean
            attack_pkt_max = fwd_pkt_max
            attack_pkt_std = fwd_pkt_std
            attack_dir = "fwd"
        else:
            attack_rate = bwd_pkts_s
            response_rate = fwd_pkts_s
            attack_pkt_mean = bwd_pkt_max  # Use max as proxy for bwd mean
            attack_pkt_max = bwd_pkt_max
            attack_pkt_std = bwd_pkt_std
            attack_dir = "bwd"

        # Also check raw packet counts for sustained floods
        attack_pkts = max(subflow_fwd, subflow_bwd)
        response_pkts = min(subflow_fwd, subflow_bwd)

        # Standard web ports — asymmetric TCP traffic is NORMAL (web browsing)
        # BUT: UDP on port 80 is NEVER normal — it's likely a flood attack
        # So is_web_port only applies to TCP connections
        is_web_port = dst_port in {80, 443, 8080, 8443} and protocol == 'TCP'

        if attack_rate > 10000:
            dos_score += 3
            dos_reasons.append(f"extreme {attack_dir} rate {attack_rate:.0f} pkt/s")
        elif attack_rate > 1000:
            dos_score += 2
            dos_reasons.append(f"high {attack_dir} rate {attack_rate:.0f} pkt/s")
        elif attack_rate > 100 and not is_web_port:
            dos_score += 1
            dos_reasons.append(f"elevated {attack_dir} rate {attack_rate:.0f} pkt/s")

        if response_rate == 0 and attack_rate > 50:
            dos_score += 2
            dos_reasons.append("completely unidirectional (zero response)")
        elif response_rate < attack_rate * 0.05 and attack_rate > 100 and not is_web_port:
            dos_score += 1
            dos_reasons.append(f"heavily asymmetric ({attack_rate:.0f} vs {response_rate:.0f})")

        if attack_pkt_mean > 500 and attack_rate > 200:
            dos_score += 2
            dos_reasons.append(f"large flood packets ({attack_pkt_mean:.0f}B)")
        elif attack_pkt_mean > 200 and attack_rate > 100 and not is_web_port:
            dos_score += 1
            dos_reasons.append(f"moderate flood packets ({attack_pkt_mean:.0f}B)")

        if attack_pkts > 50 and response_pkts == 0:
            dos_score += 2
            dos_reasons.append(f"flood packet count ({attack_pkts} with zero response)")
        elif attack_pkts > 50 and response_pkts <= 2 and not is_web_port:
            dos_score += 1
            dos_reasons.append(f"high packet count ({attack_pkts} with {response_pkts} response)")

        if ack_flag == 0 and protocol == 'TCP' and attack_rate > 100:
            dos_score += 1
            dos_reasons.append("no ACK flag (SYN flood pattern)")

        if init_fwd_win == 0 and init_bwd_win == 0 and protocol == 'TCP':
            dos_score += 1
            dos_reasons.append("no TCP window negotiation")

        if flow_duration < 100000 and attack_rate > 1000:
            dos_score += 1
            dos_reasons.append("short burst flood")

        if dos_score >= 5:
            # Determine specific DoS sub-type
            if protocol == 'UDP' and attack_pkt_mean > 500:
                dos_type = "DoS attacks-Hulk"  # UDP flood with large packets = Hulk
            elif protocol == 'UDP':
                dos_type = "DDOS attack-HOIC"   # UDP flood with small packets = HOIC
            elif attack_pkt_mean > 800 and attack_rate > 1000:
                dos_type = "DoS attacks-Hulk"
            elif attack_rate > 10000 and attack_pkt_mean < 200:
                dos_type = "DDoS attacks-LOIC-HTTP"
            elif flow_duration > 500000 and attack_rate < 100:
                dos_type = "DoS attacks-SlowHTTPTest"
            elif attack_pkt_mean > 500 and attack_rate > 500:
                dos_type = "DoS attacks-GoldenEye"
            elif dst_port == 80 or dst_port == 8080:
                dos_type = "DDoS attacks-LOIC-HTTP"
            else:
                dos_type = "DDOS attack-HOIC"
            return {'is_attack': True, 'is_suspicious': False,
                    'attack_type': dos_type,
                    'confidence': min(0.90 + dos_score * 0.01, 0.98),
                    'reason': '; '.join(dos_reasons[:3])}

        if dos_score >= 3:
            return {'is_attack': False, 'is_suspicious': True,
                    'attack_type': 'DDoS Attack',
                    'confidence': 0.70 + dos_score * 0.03,
                    'reason': '; '.join(dos_reasons[:2])}

        # ==================================================================
        # PATTERN 2: BRUTE FORCE / CREDENTIAL STUFFING
        # Signature: Many small packets, regular intervals, targeted auth ports,
        #            high forward count, low backward, moderate rate
        # REQUIRES auth port - random web ports should NOT trigger this
        # ==================================================================
        brute_score = 0
        brute_reasons = []

        auth_ports = {22, 23, 21, 3389, 1433, 3306, 5432, 445}
        is_auth_port = dst_port in auth_ports

        if is_auth_port:
            brute_score += 2  # Auth port is a strong signal
            brute_reasons.append(f"auth-targeted port {dst_port}")

        if fwd_pkts_s > 50 and fwd_pkt_mean < 300 and is_auth_port:
            brute_score += 2
            brute_reasons.append(f"rapid small packets to auth port ({fwd_pkt_mean:.0f}B, {fwd_pkts_s:.0f}/s)")
        elif fwd_pkts_s > 200 and fwd_pkt_mean < 250:
            # Very high rate with small packets even on non-auth port
            brute_score += 1
            brute_reasons.append(f"high rate small packets ({fwd_pkt_mean:.0f}B, {fwd_pkts_s:.0f}/s)")

        if fwd_iat_std < fwd_iat_mean * 0.4 and fwd_iat_mean > 0 and fwd_iat_mean < 500_000:
            brute_score += 1
            brute_reasons.append("regular fast timing (automated tool)")

        if subflow_fwd > 20 and fwd_pkt_std < 40:
            brute_score += 1
            brute_reasons.append("many uniform packets (repeated login attempts)")

        if bwd_pkts_s > 0 and bwd_pkt_max < 150 and is_auth_port:
            brute_score += 1
            brute_reasons.append("small responses (auth rejections)")

        if brute_score >= 5:
            if dst_port == 22:
                brute_type = "SSH-Bruteforce"
            elif dst_port == 21:
                brute_type = "FTP-BruteForce"
            elif dst_port == 3389:
                brute_type = "RDP Brute Force"
            else:
                brute_type = "Brute Force Attack"
            return {'is_attack': True, 'is_suspicious': False,
                    'attack_type': brute_type,
                    'confidence': min(0.85 + brute_score * 0.02, 0.95),
                    'reason': '; '.join(brute_reasons[:3])}

        # ==================================================================
        # PATTERN 3: BOTNET C2 COMMUNICATION
        # Signature: Low/moderate rate, small packets, BIDIRECTIONAL,
        #            LONG duration, REGULAR beacons, NON-STANDARD ports
        # CRITICAL: Normal HTTPS keep-alive looks like C2 beacons!
        # Standard ports (443, 80) need MUCH stricter thresholds.
        # ==================================================================
        c2_score = 0
        c2_reasons = []
        is_standard_port = dst_port in {80, 443, 8443, 8080, 53}
        has_long_duration = flow_duration > 30_000_000  # > 30 seconds (was 5s — too loose)
        has_regular_beacons = (fwd_iat_std < fwd_iat_mean * 0.2 and
                               fwd_iat_mean > 500_000) if fwd_iat_mean > 0 else False

        # On standard ports, C2 is very unlikely — only flag with extreme evidence
        if is_standard_port:
            # Standard port — need VERY strong signals (>60s, extremely regular)
            if flow_duration > 60_000_000 and has_regular_beacons:
                c2_score += 2
                c2_reasons.append(f"suspicious long session on standard port ({flow_duration/1e6:.0f}s)")
            if 0 < fwd_pkts_s < 5 and 0 < bwd_pkts_s < 5 and fwd_pkt_mean < 100:
                c2_score += 1
                c2_reasons.append("extremely low rate tiny packets")
        else:
            # Non-standard port — normal C2 detection
            if 0 < fwd_pkts_s < 50 and 0 < bwd_pkts_s < 50:
                c2_score += 1
                c2_reasons.append(f"low bidirectional rate ({fwd_pkts_s:.1f}/{bwd_pkts_s:.1f} pkt/s)")

            if fwd_pkt_mean < 200 and bwd_pkt_max < 500:
                c2_score += 1
                c2_reasons.append("small command/response packets")

            if has_long_duration:
                c2_score += 2
                c2_reasons.append(f"persistent connection ({flow_duration/1e6:.1f}s)")

            if has_regular_beacons:
                c2_score += 2
                c2_reasons.append("regular beacon intervals")

            if ack_flag > 0 and init_fwd_win > 0:
                c2_score += 1
                c2_reasons.append("established TCP session")

        c2_ports = {6667, 9001, 2375, 4444, 1337}
        if dst_port in c2_ports and c2_score >= 2:
            c2_score += 2
            c2_reasons.append(f"known C2 port {dst_port}")

        if c2_score >= 5 and has_long_duration:
            return {'is_attack': True, 'is_suspicious': False,
                    'attack_type': 'Botnet C2 Communication',
                    'confidence': min(0.85 + c2_score * 0.02, 0.95),
                    'reason': '; '.join(c2_reasons[:3])}

        # ==================================================================
        # PATTERN 4: PORT SCANNING / RECONNAISSANCE
        # Signature: Many short flows, minimal data, wide port range
        # ==================================================================
        scan_score = 0
        scan_reasons = []

        if flow_duration < 50000 and subflow_fwd <= 2:  # Very short probes
            scan_score += 2
            scan_reasons.append("very short flow with minimal packets")

        if fwd_pkt_mean < 80 and bwd_pkt_max < 80:
            scan_score += 1
            scan_reasons.append("tiny packets (probe-like)")

        if init_fwd_win > 0 and bwd_pkts_s == 0:
            scan_score += 1
            scan_reasons.append("SYN sent but no response")

        if fwd_act_data == 0 and subflow_fwd > 0:
            scan_score += 1
            scan_reasons.append("no data payload (pure probe)")

        if scan_score >= 4:
            return {'is_attack': True, 'is_suspicious': False,
                    'attack_type': 'Port Scanning',
                    'confidence': min(0.80 + scan_score * 0.03, 0.92),
                    'reason': '; '.join(scan_reasons[:3])}

        # ==================================================================
        # PATTERN 5: SQL INJECTION / DATABASE ATTACK
        # Signature: Targets DB ports, large varied request payloads
        # Checked BEFORE exfiltration because DB port + large inbound = injection
        # ==================================================================
        db_ports = {1433, 3306, 5432, 27017}
        if dst_port in db_ports and fwd_pkt_mean > 400 and fwd_pkt_std > 100:
            return {'is_attack': True, 'is_suspicious': False,
                    'attack_type': 'SQL Injection',
                    'confidence': 0.88,
                    'reason': f"large varied payloads ({fwd_pkt_mean:.0f}B avg, "
                              f"std={fwd_pkt_std:.0f}) to DB port {dst_port}"}

        # ==================================================================
        # PATTERN 6: DATA EXFILTRATION
        # Signature: Very high outbound data, low inbound, sustained, TCP only
        # UDP with large packets = DoS flood, NOT exfiltration
        # Excludes DB ports AND standard web ports
        # ==================================================================
        standard_web_ports = {80, 443, 8080, 8443, 53, 853}
        is_normal_web = dst_port in standard_web_ports
        if (protocol == 'TCP' and fwd_pkt_mean > 800 and bwd_pkt_max < 200 and
            flow_duration > 1_000_000 and fwd_pkts_s < 500 and
            dst_port not in db_ports and not is_normal_web):
            return {'is_attack': True, 'is_suspicious': False,
                    'attack_type': 'Data Exfiltration',
                    'confidence': 0.85,
                    'reason': f"large outbound ({fwd_pkt_mean:.0f}B avg), "
                              f"minimal inbound, sustained flow"}

        # ==================================================================
        # PATTERN 7: INFILTRATION (slow, stealthy)
        # Signature: Very low rate, long duration, uses standard ports
        # Exclude known benign discovery ports (mDNS, SSDP, LLMNR, DHCP)
        # ==================================================================
        benign_discovery_ports = {80, 443, 53, 5353, 1900, 5355, 137, 138, 139, 67, 68, 547, 546}
        if (flow_duration > 10_000_000 and fwd_pkts_s < 10 and bwd_pkts_s < 10 and
            fwd_pkt_mean > 200 and dst_port not in benign_discovery_ports):
            return {'is_attack': False, 'is_suspicious': True,
                    'attack_type': 'Infiltration',
                    'confidence': 0.70,
                    'reason': 'slow stealthy traffic on non-standard port'}

        # ==================================================================
        # NO PATTERN MATCHED STRONGLY - likely normal
        # Only flag as suspicious if a pattern scored >= 3 (meaningful signal)
        # ==================================================================
        max_score = max(dos_score, brute_score, c2_score, scan_score)
        if max_score >= 3:
            scores = {'DDoS Attack': dos_score, 'Brute Force Attack': brute_score,
                      'Botnet C2 Communication': c2_score, 'Port Scanning': scan_score}
            best = max(scores, key=scores.get)
            return {'is_attack': False, 'is_suspicious': True,
                    'attack_type': best,
                    'confidence': 0.55 + max_score * 0.05,
                    'reason': 'weak behavioural indicators - needs further analysis'}

        return {'is_attack': False, 'is_suspicious': False,
                'attack_type': 'Normal', 'confidence': 0.88,
                'reason': 'no anomalous behavioural patterns detected'}

    # =========================================================================
    #  SEARCH-BASED CLASSIFICATION (secondary)
    # =========================================================================
    def _classify_from_search(self, search_results):
        """Classify based on search results - secondary to behaviour."""
        if not search_results:
            return None
        search_text = ' '.join([
            f"{r.get('title', '')} {r.get('snippet', '')}"
            for r in search_results
        ]).lower()

        patterns = [
            (['reverse shell', 'backdoor', 'meterpreter'],    'Reverse Shell Attack', 0.82),
            (['botnet', 'c2', 'command and control', 'c&c'],  'Botnet C2 Communication', 0.80),
            (['ransomware', 'encrypt', 'ransom'],              'Ransomware Activity', 0.85),
            (['data exfiltration', 'data theft', 'exfil'],     'Data Exfiltration', 0.78),
            (['brute force', 'password', 'credential'],        'Brute Force Attack', 0.75),
            (['sql injection', 'sqli', 'database attack'],     'SQL Injection Attack', 0.80),
            (['exploit', 'cve', 'vulnerability', 'rce'],       'Exploit Attempt', 0.78),
            (['trojan', 'malware', 'virus'],                   'Malware Communication', 0.80),
            (['ddos', 'denial of service', 'flood'],           'DDoS Attack', 0.82),
            (['port scan', 'reconnaissance', 'scanning'],      'Port Scanning', 0.72),
            (['cryptominer', 'mining', 'crypto'],              'Cryptominer Activity', 0.78),
        ]
        for keywords, attack_type, conf in patterns:
            if any(kw in search_text for kw in keywords):
                matched = [kw for kw in keywords if kw in search_text][0]
                return {'type': attack_type, 'confidence': conf,
                        'reason': f"Threat intel match: {matched}"}
        return None

    # =========================================================================
    #  OLLAMA LLM ANALYSIS (enrichment)
    # =========================================================================
    def _analyze_with_ollama(self, traffic_data: dict, features: dict, search_results: list) -> dict:
        """Use Ollama for enrichment on uncertain cases.
        Prompt includes FULL behavioural features so LLM can reason properly."""
        search_context = "\n".join([
            f"- {r['title']}: {r['snippet'][:150]}"
            for r in search_results
        ]) if search_results else "No threat intelligence found."

        # Extract the key features the LLM needs to see
        f = features if isinstance(features, dict) else {}
        prompt = f"""You are a network security analyst. Classify this traffic.

FLOW FEATURES:
- Dst Port: {f.get('Dst Port', 0)}
- Protocol: {traffic_data.get('protocol', '?')}
- Fwd Packets/sec: {f.get('Fwd Pkts/s', 0):.1f}
- Bwd Packets/sec: {f.get('Bwd Pkts/s', 0):.1f}
- Fwd Pkt Size Mean: {f.get('Fwd Pkt Len Mean', 0):.1f} bytes
- Fwd Pkt Size Max: {f.get('Fwd Pkt Len Max', 0):.1f} bytes
- Bwd Pkt Size Max: {f.get('Bwd Pkt Len Max', 0):.1f} bytes
- Flow Duration: {f.get('Flow Duration', 0):.0f} microseconds
- Flow IAT Mean: {f.get('Flow IAT Mean', 0):.1f} us
- ACK Flag: {f.get('ACK Flag Cnt', 0)}
- Init Fwd Window: {f.get('Init Fwd Win Byts', 0)}
- Init Bwd Window: {f.get('Init Bwd Win Byts', 0)}
- Subflow Fwd Pkts: {f.get('Subflow Fwd Pkts', 0)}
- Subflow Bwd Pkts: {f.get('Subflow Bwd Pkts', 0)}
- Fwd Header Len: {f.get('Fwd Header Len', 0)}

CONNECTION:
- Source: {traffic_data.get('src_ip', '?')}:{traffic_data.get('src_port', '?')}
- Dest: {traffic_data.get('dst_ip', '?')}:{traffic_data.get('dst_port', '?')}
- ML said: {traffic_data.get('ml_prediction', '?')} ({traffic_data.get('ml_confidence', 0):.0%})

THREAT INTEL:
{search_context}

CLASSIFICATION RULES:
- HIGH fwd rate (>1000/s) + large packets + no backward = DoS/DDoS
- LOW rate (<50/s) + bidirectional + small packets + long duration = Botnet C2
- Moderate rate + small uniform packets + auth port = Brute Force
- Short flow + tiny packets + no data = Port Scanning
- Large outbound + little inbound + sustained = Data Exfiltration
- Port alone does NOT determine attack type. BEHAVIOUR determines attack type.

RESPOND EXACTLY (one line each):
ATTACK_TYPE: [Normal OR specific type like DoS attacks-Hulk, SSH-Bruteforce, Botnet C2 Communication, etc.]
CONFIDENCE: [0.5 to 0.95]
REASON: [one sentence based on features]"""

        try:
            response = self._query_ollama(prompt)
            result = self._parse_response(response, search_results)

            if result.get('attack_category') in ['Suspicious Activity', 'Suspicious', 'Unknown']:
                result['attack_category'] = 'Normal'
                result['is_suspicious'] = False
                result['is_zero_day'] = False
                result['confidence'] = 0.75
            return result
        except Exception as e:
            return self._result(False, "Normal", 0.70, f"LLM error: {e}")

    # =========================================================================
    #  SAFE TRAFFIC CHECK
    # =========================================================================
    def _is_safe_traffic(self, src_ip: str, dst_ip: str, dst_port: int) -> str:
        """Check if traffic is safe and should NOT be flagged.
        - Multicast/Broadcast on known discovery ports: ALWAYS safe
        - Local-to-local: NEVER safe.
        - External on standard ports: SAFE."""

        # ─── Multicast & Broadcast (benign OS-level protocols) ───
        benign_multicast_ports = {5353, 1900, 5355, 547, 546}
        benign_broadcast_ports = {137, 138, 139, 67, 68, 1900}

        is_multicast = dst_ip.startswith(('224.', '225.', '226.', '227.',
                                          '228.', '229.', '230.', '231.',
                                          '232.', '233.', '234.', '235.',
                                          '236.', '237.', '238.', '239.'))
        is_broadcast = dst_ip == '255.255.255.255' or dst_ip.endswith('.255')

        if is_multicast and dst_port in benign_multicast_ports:
            return 'Network Discovery (Multicast)'
        if is_broadcast and dst_port in benign_broadcast_ports:
            return 'Network Discovery (Broadcast)'

        local_prefixes = ('192.168.', '10.', '172.16.', '172.17.',
                    '172.18.', '172.19.', '172.20.', '172.21.', '172.22.',
                    '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
                    '172.28.', '172.29.', '172.30.', '172.31.', '127.')
        safe_ports = {443, 80, 53, 853, 8443}
        
        src_local = src_ip.startswith(local_prefixes)
        dst_local = dst_ip.startswith(local_prefixes)
        
        if src_local and dst_local:
            return None  # Local-to-local = NEVER safe
        
        # External traffic on standard ports = normal web browsing
        if src_local and not dst_local and dst_port in safe_ports:
            return 'External Web Service'
        if not src_local and dst_local and dst_port in safe_ports:
            return 'External Web Service'
        
        return None

    # =========================================================================
    #  THREAT INTELLIGENCE SEARCH
    # =========================================================================
    def _search_threat_intel(self, port, protocol, features):
        current_time = time.time()
        if current_time - self.last_search_time < self.min_search_interval:
            return self._get_known_threats(port)
        self.last_search_time = current_time

        try:
            queries = self._build_search_queries(port, protocol, features)
            results = []
            for query in queries[:2]:
                print(f"{Fore.CYAN}   🔎 Query: {query[:50]}...{Style.RESET_ALL}")
                r = self._duckduckgo_search(query)
                results.extend(r)
                if r:
                    print(f"{Fore.GREEN}   ✓ {len(r)} results{Style.RESET_ALL}")
                time.sleep(0.5)
            if not results:
                results = self._get_known_threats(port)
            return results[:5]
        except Exception as e:
            print(f"{Fore.YELLOW}   ⚠️ Search error: {e}{Style.RESET_ALL}")
            return self._get_known_threats(port)

    def _build_search_queries(self, port, protocol, features):
        queries = []
        port_queries = {
            4444: "metasploit port 4444 reverse shell attack",
            5555: "android debug bridge port 5555 exploit",
            6667: "irc botnet port 6667 malware",
            22: "ssh brute force attack detection",
            23: "telnet attack exploit vulnerability",
            3389: "rdp brute force attack CVE",
            445: "smb eternal blue wannacry attack",
            27017: "mongodb exposed attack",
            6379: "redis unauthorized access exploit",
        }
        if port in port_queries:
            queries.append(port_queries[port])
        else:
            queries.append(f"port {port} cyber attack vulnerability CVE")

        f = features if isinstance(features, dict) else {}
        fwd_pkts = f.get('Fwd Pkts/s', 0) or 0
        bwd_pkts = f.get('Bwd Pkts/s', 0) or 0
        if fwd_pkts > 1000:
            queries.append("denial of service flood attack detection")
        elif fwd_pkts > 0 and bwd_pkts > 0 and fwd_pkts < 50:
            queries.append("command and control beacon traffic detection")
        return queries

    def _duckduckgo_search(self, query):
        results = []
        try:
            api_url = f"https://api.duckduckgo.com/?q={requests.utils.quote(query)}&format=json&no_html=1"
            response = requests.get(api_url, timeout=10, headers={'User-Agent': 'PIDS-ThreatIntel/3.0'})
            if response.status_code == 200:
                data = response.json()
                if data.get('Abstract'):
                    results.append({'title': data.get('Heading', query),
                                    'snippet': data.get('Abstract', '')[:300], 'source': 'DuckDuckGo API'})
                for topic in data.get('RelatedTopics', [])[:3]:
                    if isinstance(topic, dict) and topic.get('Text'):
                        results.append({'title': topic.get('FirstURL', '').split('/')[-1].replace('_', ' '),
                                        'snippet': topic.get('Text', '')[:300], 'source': 'DuckDuckGo'})
            if len(results) < 2:
                results.extend(self._duckduckgo_html_search(query))
            return results[:5]
        except Exception:
            return self._duckduckgo_html_search(query)

    def _duckduckgo_html_search(self, query):
        results = []
        try:
            url = "https://html.duckduckgo.com/html/"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.post(url, data={'q': query}, headers=headers, timeout=10)
            if response.status_code == 200:
                html = response.text
                snippets = re.findall(r'<a class="result__snippet"[^>]*>(.*?)</a>', html, re.DOTALL)
                titles = re.findall(r'<a class="result__a"[^>]*>(.*?)</a>', html, re.DOTALL)
                for title, snippet in zip(titles[:3], snippets[:3]):
                    title = re.sub(r'<[^>]+>', '', title).strip()
                    snippet = re.sub(r'<[^>]+>', '', snippet).strip()
                    if title and snippet:
                        results.append({'title': title, 'snippet': snippet[:300], 'source': 'DuckDuckGo HTML'})
        except Exception:
            pass
        return results

    def _get_known_threats(self, port):
        known = {
            4444: [{"title": "Metasploit Default Port", "snippet": "Port 4444 is default for Metasploit reverse TCP shells.", "source": "Threat DB"}],
            5555: [{"title": "Android Debug Bridge", "snippet": "Port 5555 ADB exposure allows remote code execution.", "source": "Threat DB"}],
            6667: [{"title": "IRC Botnet C2", "snippet": "Port 6667 IRC used for botnet command and control.", "source": "Threat DB"}],
            6379: [{"title": "Redis Unauthorized", "snippet": "Port 6379 Redis without auth allows RCE.", "source": "Threat DB"}],
            27017: [{"title": "MongoDB Exposed", "snippet": "Port 27017 MongoDB without auth allows data breach.", "source": "Threat DB"}],
            2375: [{"title": "Docker API", "snippet": "Port 2375 Docker API without TLS allows container escape.", "source": "Threat DB"}],
        }
        return known.get(port, [{"title": f"Port {port}", "snippet": f"Traffic on port {port}.", "source": "Threat DB"}])

    # =========================================================================
    #  HELPERS
    # =========================================================================
    def _result(self, is_attack, category, confidence, reasoning):
        return {
            "success": True,
            "is_suspicious": is_attack,
            "is_zero_day": is_attack,
            "attack_category": category,
            "confidence": confidence,
            "reasoning": reasoning
        }

    def _query_ollama(self, prompt):
        url = f"{self.ollama_host}/api/generate"
        payload = {
            "model": self.ollama_model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": 150, "num_ctx": 1024, "num_thread": 2}
        }
        response = requests.post(url, json=payload, timeout=30)
        response.raise_for_status()
        return response.json().get('response', '').strip()

    def zero_day_scan(self, port: int, protocol: str = 'TCP',
                      src_ip: str = '', dst_ip: str = '',
                      features: dict = None) -> dict:
        """
        Run the full zero-day-detection workflow end-to-end and return
        a step-by-step trace the frontend can visualise.

        The workflow is the same one ``analyze_zero_day`` runs internally
        on suspicious live traffic, exposed here as a user-triggered
        scan from the UI.

        Returns
        -------
        dict
            ``{
                success: bool,
                ollama_available: bool,
                steps: [
                    {step: 'safety_check',  ...},
                    {step: 'build_queries', ...},
                    {step: 'duckduckgo',    ...},
                    {step: 'behavioural',   ...},
                    {step: 'llm_analysis',  ...},
                    {step: 'verdict',       ...},
                ],
                verdict: { is_attack, attack_category, confidence, reasoning }
            }``
        """
        import time as _time
        features = features or {}
        steps = []

        # 1. SAFETY CHECK — known-safe IPs / services bypass everything.
        safe_check = self._is_safe_traffic(src_ip, dst_ip, port)
        steps.append({
            'step': 'safety_check', 'label': 'Safety check',
            'duration_ms': 0,
            'result': {
                'is_safe': bool(safe_check),
                'reason': safe_check or 'Not on known-safe whitelist; continuing scan.',
            },
        })

        # 2. BUILD SEARCH QUERIES.
        t0 = _time.time()
        queries = self._build_search_queries(port, protocol, features)
        steps.append({
            'step': 'build_queries', 'label': 'Build threat-intel queries',
            'duration_ms': round((_time.time() - t0) * 1000),
            'result': {'queries': queries},
        })

        # 3. DUCKDUCKGO SEARCH (only if not whitelisted).
        ddg_results = []
        if not safe_check:
            t0 = _time.time()
            try:
                for q in queries[:2]:
                    rs = self._duckduckgo_search(q)
                    ddg_results.append({'query': q, 'hits': rs})
                    _time.sleep(0.3)
            except Exception as exc:
                ddg_results.append({'query': '(error)', 'hits': [],
                                    'error': str(exc)})
            steps.append({
                'step': 'duckduckgo', 'label': 'DuckDuckGo open-source threat intel',
                'duration_ms': round((_time.time() - t0) * 1000),
                'result': {'searches': ddg_results,
                           'total_hits': sum(len(d.get('hits', [])) for d in ddg_results)},
            })

        # 4. BEHAVIOURAL FEATURE ANALYSIS (the project's "core fix" path).
        t0 = _time.time()
        behaviour = self._analyse_behaviour(features, protocol)
        steps.append({
            'step': 'behavioural', 'label': 'Behavioural feature analysis',
            'duration_ms': round((_time.time() - t0) * 1000),
            'result': {
                'is_attack': bool(behaviour.get('is_attack')),
                'attack_type': behaviour.get('attack_type', ''),
                'confidence': float(behaviour.get('confidence', 0.0)),
                'reason': behaviour.get('reason', ''),
            },
        })

        # 5. LLM (Ollama) ANALYSIS — only if Ollama is up and not pre-resolved.
        llm_analysis = None
        if self.ollama_available and not safe_check:
            t0 = _time.time()
            try:
                flat_hits = []
                for d in ddg_results:
                    flat_hits.extend(d.get('hits', []))
                llm_analysis = self._analyze_with_ollama(
                    {'src_ip': src_ip, 'dst_ip': dst_ip,
                     'dst_port': port, 'protocol': protocol},
                    features,
                    flat_hits,
                )
            except Exception as exc:
                llm_analysis = {'error': str(exc)}
            steps.append({
                'step': 'llm_analysis', 'label': 'Llama behavioural reasoning',
                'duration_ms': round((_time.time() - t0) * 1000),
                'result': llm_analysis,
            })
        else:
            steps.append({
                'step': 'llm_analysis', 'label': 'Llama behavioural reasoning',
                'duration_ms': 0,
                'result': {'skipped': True,
                           'reason': 'Ollama unavailable' if not self.ollama_available
                                     else 'Pre-resolved by safety check'},
            })

        # 6. FINAL VERDICT — combine all signals (re-uses analyze_zero_day).
        t0 = _time.time()
        try:
            verdict = self.analyze_zero_day(
                {'src_ip': src_ip, 'dst_ip': dst_ip, 'dst_port': port,
                 'protocol': protocol, 'skip_cache': True},
                features,
            )
        except Exception as exc:
            verdict = {'success': False, 'error': str(exc),
                       'attack_category': 'Unknown', 'confidence': 0.0,
                       'reasoning': '', 'is_suspicious': False, 'is_zero_day': False}
        steps.append({
            'step': 'verdict', 'label': 'Final verdict',
            'duration_ms': round((_time.time() - t0) * 1000),
            'result': verdict,
        })

        return {
            'success': True,
            'ollama_available': self.ollama_available,
            'port': port, 'protocol': protocol,
            'src_ip': src_ip, 'dst_ip': dst_ip,
            'steps': steps,
            'verdict': {
                'is_attack': bool(verdict.get('is_suspicious') or verdict.get('is_zero_day')),
                'attack_category': verdict.get('attack_category', 'Unknown'),
                'confidence': float(verdict.get('confidence', 0.0)),
                'reasoning': verdict.get('reasoning', ''),
            },
        }

    def comprehensive_recheck(self, log_info: dict, features: dict) -> dict:
        """
        End-to-end LLM-driven re-classification of a single flagged flow.

        Unlike :meth:`analyze_zero_day` (which is invoked from the live
        capture pipeline and uses cached / heuristic shortcuts to stay
        fast), this method builds a rich context-aware prompt and sends
        EVERYTHING to Llama, then parses a strict JSON verdict.

        Used by ``views.recheck_with_llm`` when
        ``settings.LLM_RECHECK_MODE == 'pure'`` (default — implements
        the user's "re-check fully by the Llama" requirement).

        Parameters
        ----------
        log_info : dict
            ``src_ip``, ``dst_ip``, ``src_port``, ``dst_port``,
            ``protocol``, ``ml_prediction``, ``ml_confidence``,
            ``original_status``.
        features : dict
            31-feature flow vector from the extractor.

        Returns
        -------
        dict
            ``{success, is_attack, attack_category, confidence, reasoning,
            llm_raw}``. ``success=False`` if Ollama is unreachable or
            the response can't be parsed.
        """
        if not self.ollama_available:
            return {"success": False, "error": "ollama_unavailable"}

        prompt = self._build_recheck_prompt(log_info, features)
        try:
            raw = self.generate_text(
                prompt=prompt,
                max_tokens=350,
                temperature=0.2,        # low temp — verdicts should be stable
                num_ctx=3072,
                # Generous timeout: the FIRST recheck after Ollama starts has
                # to cold-load the model into memory, which can take far
                # longer than a warm generation. 60s was too tight and
                # surfaced as "LLM recheck failed" on the first click.
                timeout=120,
            )
        except Exception as exc:
            return {"success": False, "error": f"llm_call_failed: {exc}"}

        if not raw:
            return {"success": False, "error": "empty_response"}

        verdict = self._parse_recheck_json(raw)
        if verdict is None:
            return {"success": False, "error": "unparseable_response", "llm_raw": raw[:300]}

        verdict["success"] = True
        verdict["llm_raw"] = raw
        return verdict

    def _build_recheck_prompt(self, log_info: dict, features: dict) -> str:
        """
        Build the prompt for :meth:`comprehensive_recheck`.

        Annotates flow context (multicast / malicious port / known
        service) so the LLM has the same information the legacy
        heuristic bypasses had — but the LLM, not Python branches,
        weighs the evidence.
        """
        src_ip   = log_info.get('src_ip', '')   or ''
        dst_ip   = log_info.get('dst_ip', '')   or ''
        src_port = log_info.get('src_port', 0)  or 0
        dst_port = log_info.get('dst_port', 0)  or 0
        proto    = log_info.get('protocol', '?')
        ml_pred  = log_info.get('ml_prediction', 'Unknown')
        ml_conf  = log_info.get('ml_confidence', 0.0) or 0.0

        # ---- Annotate the flow context ----
        notes = []
        # IP class
        if dst_ip.startswith(('224.', '225.', '226.', '227.', '228.', '229.',
                              '230.', '231.', '232.', '233.', '234.', '235.',
                              '236.', '237.', '238.', '239.')):
            notes.append(f"Destination {dst_ip} is an IPv4 multicast address — "
                         "typically used by mDNS / SSDP / LLMNR / DHCP discovery, "
                         "which are benign OS-level protocols.")
        if dst_ip == '255.255.255.255' or dst_ip.endswith('.255'):
            notes.append(f"Destination {dst_ip} is a broadcast address — "
                         "typically used by DHCP / NetBIOS / ARP, "
                         "which are benign network discovery protocols.")
        # Port semantics
        well_known_benign = {
            53: 'DNS', 67: 'DHCP-server', 68: 'DHCP-client', 80: 'HTTP', 123: 'NTP',
            137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN',
            443: 'HTTPS / QUIC', 1900: 'SSDP / UPnP', 5353: 'mDNS', 5355: 'LLMNR',
            8080: 'HTTP-alt', 8443: 'HTTPS-alt',
        }
        well_known_attack = {
            4444: 'Metasploit reverse-shell', 1337: 'leet backdoor',
            31337: 'Back Orifice trojan', 5555: 'Android ADB exploit',
            6667: 'IRC botnet C2', 9001: 'Tor hidden service',
            2375: 'Docker API (insecure)', 6379: 'Redis (auth-bypass)',
            27017: 'MongoDB (auth-bypass)',
        }
        auth_ports = {22: 'SSH', 23: 'Telnet', 21: 'FTP', 3389: 'RDP',
                      1433: 'MSSQL', 3306: 'MySQL', 5432: 'PostgreSQL', 445: 'SMB'}
        if dst_port in well_known_benign:
            notes.append(f"Port {dst_port} = {well_known_benign[dst_port]} (well-known benign service).")
        if dst_port in well_known_attack:
            notes.append(f"Port {dst_port} = {well_known_attack[dst_port]} "
                         "(EXCLUSIVELY associated with attacker tooling — strong attack signal).")
        if dst_port in auth_ports:
            notes.append(f"Port {dst_port} = {auth_ports[dst_port]} (authentication service — "
                         "common brute-force / credential-stuffing target).")
        # Rate-based hint — STRONG warning. Small LLMs (Llama 3.2:1b) tend to
        # downgrade these incorrectly because per-flow features look "normal"
        # even when the FLOW RATE itself is the attack signature.
        if any(kw in (ml_pred or '').lower() for kw in ('brute', 'flood', 'loic', 'hoic', 'ddos', 'dos', 'hulk', 'goldeneye', 'slowloris', 'slowhttp', 'slow', 'low-and-slow', 'anomalous')):
            notes.append(
                "*** STRONG WARNING: the original ML verdict is from the rate-based "
                "family (DoS / DDoS / brute-force). The attack signature for this "
                "family is HIGH FLOW RATE, which you CANNOT see in a single packet's "
                "feature dict. Per-flow values may look 'normal' while the ATTACK "
                "ITSELF is the volume of these flows arriving. Default to TRUSTING "
                f"the ML verdict ({ml_pred}, {ml_conf:.0%}) unless you have "
                "OVERWHELMING evidence of misclassification — and 'destination port "
                "is common for X' is NOT overwhelming evidence."
            )

        # ---- Helper: safe float lookup from the feature dict ----
        def _f(key, default=0.0):
            if not isinstance(features, dict):
                return default
            try:
                return float(features.get(key, default))
            except (TypeError, ValueError):
                return default

        # ---- Derived, human-readable metrics ----
        # CICFlowMeter reports durations / inter-arrival times in MICROSECONDS.
        # Small models misread the raw integer as seconds (e.g. "9.3e7 seconds")
        # and then hallucinate a justification, so we pre-compute the real,
        # labelled values and hand them to the model directly.
        dur_us   = _f('Flow Duration')
        dur_s    = dur_us / 1_000_000.0 if dur_us else 0.0
        tot_fwd  = _f('Tot Fwd Pkts')
        tot_bwd  = _f('Tot Bwd Pkts')
        tot_pkts = tot_fwd + tot_bwd
        bytes_fwd = _f('TotLen Fwd Pkts')
        bytes_bwd = _f('TotLen Bwd Pkts')
        flow_pps = _f('Flow Pkts/s') or _f('Fwd Pkts/s') + _f('Bwd Pkts/s')

        derived_lines = [
            f"  - Flow duration: {dur_s:.3f} seconds ({dur_us:.0f} microseconds)",
            f"  - Total packets: {tot_pkts:.0f}  (forward {tot_fwd:.0f} / backward {tot_bwd:.0f})",
            f"  - Total bytes: {bytes_fwd + bytes_bwd:.0f}  (forward {bytes_fwd:.0f} / backward {bytes_bwd:.0f})",
            f"  - Packet rate: {flow_pps:.2f} packets/second",
        ]
        # One-directional traffic (no replies) is a hallmark of flood / spoofed
        # DoS-DDoS — surface it explicitly rather than hoping the model infers it.
        if tot_fwd > 0 and tot_bwd == 0:
            derived_lines.append("  - NOTE: purely one-directional (no backward packets) — "
                                 "consistent with flood / spoofed DoS-DDoS traffic, not a normal "
                                 "two-way conversation.")

        # ---- Raw feature section (limit to keep prompt size sane) ----
        important_keys = [
            'Dst Port', 'Fwd Pkts/s', 'Bwd Pkts/s', 'Down/Up Ratio',
            'Fwd Pkt Len Mean', 'Fwd Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std',
            'Flow IAT Mean', 'Flow IAT Min', 'Fwd IAT Max',
            'SYN Flag Cnt', 'ACK Flag Cnt', 'PSH Flag Cnt', 'RST Flag Cnt',
            'Init Fwd Win Byts',
        ]
        feature_lines = []
        for k in important_keys:
            if isinstance(features, dict) and k in features:
                v = features.get(k)
                try:
                    feature_lines.append(f"  - {k}: {float(v):.4g}")
                except (TypeError, ValueError):
                    feature_lines.append(f"  - {k}: {v}")

        notes_block = "\n".join(f"- {n}" for n in notes) if notes else "- (no special context flags)"

        # Anchor the attack-category vocabulary to the ML verdict so the model
        # stops defaulting to the first item in a generic list (it was emitting
        # "Bot" for almost everything). When the ML verdict already names an
        # attack family, that family is the expected category.
        ml_is_attack = (ml_pred or '').lower() not in ('normal', 'benign', 'none', '', 'unknown')
        if ml_is_attack:
            category_guidance = (
                f"If you conclude this IS an attack, use the category \"{ml_pred}\" unless the "
                "numeric evidence clearly points to a DIFFERENT family. Do NOT invent a category "
                "such as \"Bot\" that is not supported by the evidence below."
            )
        else:
            category_guidance = (
                "Pick the single best category from: Normal, DoS, DDoS, Brute Force, "
                "Reconnaissance, Infiltration, Data Exfiltration, Reverse Shell, Botnet C2, "
                "SQL Injection, XSS, Bot, Unknown. Use \"Normal\" if it is benign."
            )

        return (
            "You are a senior security analyst performing a MANUAL RE-CHECK of a single "
            "flagged network flow.\n\n"
            "FLOW METADATA\n"
            f"  Source:      {src_ip}:{src_port}\n"
            f"  Destination: {dst_ip}:{dst_port}\n"
            f"  Protocol:    {proto}\n"
            f"  Original ML verdict: {ml_pred} (confidence {ml_conf:.2f})\n\n"
            "DERIVED METRICS (already computed for you — trust these units)\n"
            + "\n".join(derived_lines) + "\n\n"
            "CONTEXT FLAGS (consider these when deciding)\n"
            f"{notes_block}\n\n"
            "RAW FLOW FEATURES (selected)\n"
            + "\n".join(feature_lines) + "\n\n"
            "RULES — read carefully:\n"
            "1. Base your verdict and reasoning ONLY on the numbers and context flags above. "
            "Do NOT invent facts about ports, IP reputation, or what is 'typical' for bots/"
            "malware — if it is not stated above, you do not know it.\n"
            "2. Your reasoning MUST quote at least one specific value from above (e.g. the packet "
            "rate or duration in seconds) and explain what it indicates.\n"
            f"3. {category_guidance}\n"
            "4. Rate-based families (DoS, DDoS, brute-force) are defined by the VOLUME of flows, "
            "which you cannot see in one flow — so do not downgrade such an ML verdict to benign "
            "unless the evidence is overwhelming.\n\n"
            "Respond with ONLY valid JSON in this exact schema (no prose, no markdown, no code fence):\n"
            "{\n"
            "  \"is_attack\": true/false,\n"
            "  \"attack_category\": \"<the chosen category>\",\n"
            "  \"confidence\": <0.0 to 1.0>,\n"
            "  \"reasoning\": \"<2-3 sentences quoting the specific evidence you used>\"\n"
            "}\n"
        )

    def _clean_reason(self, text: str) -> str:
        """
        Sanitise the small model's reasoning text.

        llama 3.2:1b often degenerates into duplicated tokens ("normal normal",
        "traffic traffic", "false true") and malformed JSON. This pulls out the
        natural-language reasoning, strips JSON punctuation, and collapses the
        duplicated words so the operator sees a clean sentence instead of the
        raw broken blob.
        """
        import re as _re
        if not text:
            return ''
        t = str(text).strip()
        # If a "reasoning" value is embedded in a (possibly malformed) blob,
        # keep only the prose after it.
        idx = t.lower().rfind('reasoning')
        if idx != -1:
            tail = _re.sub(r'^["\s:]+', '', t[idx + len('reasoning'):])
            if len(tail) > 10:
                t = tail
        t = _re.sub(r'```[a-zA-Z]*', '', t).replace('```', '')
        for ch in '{}[]"':
            t = t.replace(ch, ' ')
        # Drop leftover JSON keys / boolean literals from a broken object.
        t = _re.sub(r'\b(is_attack|attack_category|confidence)\b\s*[:=]?', ' ', t, flags=_re.I)
        # Collapse immediate duplicate words ("normal normal" -> "normal").
        t = _re.sub(r'\b(\w+)(\s+\1\b)+', r'\1', t, flags=_re.I)
        t = _re.sub(r'\s+', ' ', t)
        t = _re.sub(r'([.,:;/])\1+', r'\1', t).strip(' .,:;-')
        if t:
            t = t[0].upper() + t[1:]
        return t[:500]

    def _situation_reason(self, is_attack: bool, attack_category: str) -> str:
        """
        Clean, situation-specific fallback reason when the model gives no usable
        prose (empty / pure-garbage output). Phrased differently per outcome.
        """
        cat = (attack_category or '').strip()
        low = cat.lower()
        if not is_attack or low in ('normal', 'benign', '', 'none', 'unknown'):
            return "No clear attack indicators in the flow behaviour; classified as benign."
        if any(k in low for k in ('ddos', 'dos', 'flood', 'hulk', 'hoic', 'loic', 'slow')):
            return (f"Flow behaviour is consistent with {cat}; rate/volume-based attacks are "
                    "confirmed across many flows, so this flow is treated as part of the attack.")
        if 'brute' in low:
            return (f"Flow behaviour is consistent with {cat}: repeated short connections to an "
                    "authentication service.")
        if any(k in low for k in ('exfil', 'reverse shell', 'metasploit', 'backdoor', 'c2', 'botnet')):
            return (f"Flow behaviour is consistent with {cat}: traffic on a known malicious port / "
                    "command-and-control pattern.")
        return f"Flow behaviour is consistent with {cat}."

    def _parse_recheck_json(self, raw: str):
        """
        Extract the structured verdict from the LLM's response.

        Tolerates leading/trailing prose, code fences, and sloppy JSON
        with trailing commas. Returns ``None`` on unrecoverable parse
        failure so the caller can degrade gracefully.
        """
        import json as _json
        import re as _re
        if not raw:
            return None
        # Strip code fences if present.
        text = _re.sub(r'```[a-zA-Z]*\n?', '', raw).replace('```', '').strip()
        # Find the first {...} block.
        match = _re.search(r'\{[\s\S]*\}', text)
        if match:
            candidate = match.group(0)
            # Repair trailing commas before } or ].
            candidate = _re.sub(r',\s*([}\]])', r'\1', candidate)
            try:
                obj = _json.loads(candidate)
                v = self._reconcile_verdict({
                    "is_attack":       bool(obj.get("is_attack")),
                    "attack_category": str(obj.get("attack_category", "Unknown")).strip() or "Unknown",
                    "confidence":      max(0.0, min(1.0, float(obj.get("confidence", 0.5)))),
                    "reasoning":       self._clean_reason(obj.get("reasoning", "")),
                })
                if len(v["reasoning"]) < 12:
                    v["reasoning"] = self._situation_reason(v["is_attack"], v["attack_category"])
                return v
            except (_json.JSONDecodeError, TypeError, ValueError):
                pass  # fall through to the lenient keyword parser below

        # ─── Fallback: the 1B model sometimes ignores the JSON schema and
        # replies in prose. Rather than 503-ing the whole recheck, salvage a
        # verdict from whatever keywords are present so the operator still
        # gets an answer. ───
        return self._salvage_recheck_verdict(text)

    def _reconcile_verdict(self, d: dict) -> dict:
        """
        Resolve the small model's self-contradictions.

        Llama 3.2:1b frequently emits ``is_attack: false`` while naming a real
        attack family (e.g. "DDoS attacks-LOIC-HTTP"), or vice versa. We trust
        the named category — it carries more signal than the boolean — and make
        ``is_attack`` agree with it so downstream verdict logic is consistent.
        """
        cat = (d.get('attack_category') or '').strip()
        low = cat.lower()
        benign = {'normal', 'benign', 'none', '', 'n/a', 'na', 'clean', 'safe'}
        if low in benign:
            d['is_attack'] = False
            d['attack_category'] = 'Normal'
        elif low and low != 'unknown':
            # A concrete attack family was named — it IS an attack regardless of
            # the boolean the model produced.
            d['is_attack'] = True
        # 'Unknown' → leave the model's boolean untouched.
        return d

    def _salvage_recheck_verdict(self, text: str):
        """Best-effort verdict extraction from a non-JSON LLM reply."""
        import re as _re
        if not text or not text.strip():
            return None
        low = text.lower()

        # Decide attack vs benign from explicit signals first.
        is_attack = None
        m = _re.search(r'"?is_attack"?\s*[:=]\s*(true|false)', low)
        if m:
            is_attack = (m.group(1) == 'true')
        if is_attack is None:
            benign_kw = ('benign', 'not an attack', 'no attack', 'normal traffic',
                         'legitimate', 'is normal', 'appears normal')
            attack_kw = ('is an attack', 'malicious', 'is suspicious', 'attack detected',
                         'intrusion', 'is attack')
            if any(k in low for k in benign_kw):
                is_attack = False
            elif any(k in low for k in attack_kw):
                is_attack = True
        if is_attack is None:
            return None  # genuinely no signal — let caller report failure

        # Attack category from the known taxonomy.
        category = 'Unknown'
        if not is_attack:
            category = 'Normal'
        else:
            for cat in ('DDoS', 'DoS', 'Brute Force', 'SQL Injection', 'XSS',
                        'Infiltration', 'Reconnaissance', 'Data Exfiltration',
                        'Reverse Shell', 'Botnet C2', 'Bot'):
                if cat.lower() in low:
                    category = cat
                    break

        # Confidence if stated, else a sensible default.
        conf = 0.7
        cm = _re.search(r'"?confidence"?\s*[:=]\s*([0-9]*\.?[0-9]+)\s*(%?)', low)
        if cm:
            try:
                val = float(cm.group(1))
                if cm.group(2) == '%' or val > 1:
                    val /= 100.0
                conf = max(0.0, min(1.0, val))
            except ValueError:
                pass

        v = self._reconcile_verdict({
            "is_attack":       bool(is_attack),
            "attack_category": category,
            "confidence":      conf,
            "reasoning":       self._clean_reason(text),
        })
        if len(v["reasoning"]) < 12:
            v["reasoning"] = self._situation_reason(v["is_attack"], v["attack_category"])
        return v

    def generate_text(self, prompt: str, max_tokens: int = 400,
                      temperature: float = 0.4, num_ctx: int = 2048,
                      timeout: int = 60) -> str:
        """
        Generic text-generation entry point for callers that just want
        prose (e.g. the report writer).

        Returns an empty string if Ollama is unreachable so callers can
        fall back to a static template without extra error handling.

        Notes
        -----
        * Higher temperature than ``_query_ollama`` because reports want
          varied phrasing, not deterministic threat verdicts.
        * Larger ``num_predict`` and ``num_ctx`` because report sections
          can run several paragraphs.
        """
        if not self.ollama_available:
            return ""
        try:
            url = f"{self.ollama_host}/api/generate"
            payload = {
                "model": self.ollama_model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": float(temperature),
                    "num_predict": int(max_tokens),
                    "num_ctx": int(num_ctx),
                    "num_thread": 2,
                },
            }
            response = requests.post(url, json=payload, timeout=timeout)
            response.raise_for_status()
            return response.json().get('response', '').strip()
        except Exception:
            return ""

    def _parse_response(self, response, search_results):
        result = {"success": True, "is_suspicious": False, "is_zero_day": False,
                  "attack_category": "Normal", "confidence": 0.75, "reasoning": "",
                  "search_results_count": len(search_results)}
        try:
            for line in response.strip().split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().upper()
                    value = value.strip()
                    if key == 'ATTACK_TYPE':
                        attack = value.strip()
                        generic = ['suspicious', 'suspicious activity', 'unknown', 'benign', 'none', '', 'n/a']
                        if attack.lower() in generic or attack.lower() == 'normal':
                            result['attack_category'] = 'Normal'
                            result['is_suspicious'] = False
                            result['is_zero_day'] = False
                        else:
                            result['attack_category'] = attack
                            result['is_suspicious'] = True
                            result['is_zero_day'] = True
                    elif key == 'CONFIDENCE':
                        try:
                            conf = float(value.replace('%', '').strip())
                            if conf > 1: conf = conf / 100
                            result['confidence'] = min(max(conf, 0.5), 0.95)
                        except Exception:
                            result['confidence'] = 0.75
                    elif key == 'REASON':
                        result['reasoning'] = value
        except Exception:
            pass
        return result

    def _get_cached(self, key):
        if key in self.cache:
            t, r = self.cache[key]
            if time.time() - t < self.cache_duration:
                return r
            del self.cache[key]
        return None

    def _cache_result(self, key, result):
        if len(self.cache) > 100:
            oldest = sorted(self.cache.items(), key=lambda x: x[1][0])[:20]
            for k, _ in oldest:
                del self.cache[k]
        self.cache[key] = (time.time(), result)

    # =========================================================================
    #  REPORT GENERATION
    # =========================================================================
    def generate_report_summary(self, stats, alerts):
        if self.ollama_available:
            return self._generate_ollama_summary(stats, alerts)
        return self._generate_basic_summary(stats, alerts)

    def _generate_ollama_summary(self, stats, alerts):
        alert_summary = ""
        if alerts:
            types = {}
            for a in alerts[:20]:
                t = a.get('attack_type', 'Unknown')
                types[t] = types.get(t, 0) + 1
            alert_summary = ", ".join([f"{k}: {v}" for k, v in types.items()])
        prompt = f"""Write a professional security report summary in 3 paragraphs.
Data: {stats.get('total_traffic', 0)} packets, {stats.get('attacks', 0)} attacks, {stats.get('normal', 0)} normal.
Attack types: {alert_summary or 'None'}
Rules: plain prose only, no markdown, no bullets, no headers."""
        try:
            response = self._query_ollama(prompt)
            response = re.sub(r'\*\*([^*]+)\*\*', r'\1', response)
            response = re.sub(r'^#+\s*', '', response, flags=re.MULTILINE)
            response = re.sub(r'^\s*[-*]\s+', '', response, flags=re.MULTILINE)
            return response.strip()
        except Exception:
            return self._generate_basic_summary(stats, alerts)

    def _generate_basic_summary(self, stats, alerts):
        total = stats.get('total_traffic', 0)
        attacks = stats.get('attacks', 0)
        normal = stats.get('normal', 0)
        rate = (attacks / max(total, 1)) * 100
        s = f"During the monitoring period, PIDS analyzed {total:,} packets. "
        s += f"The analysis identified {attacks:,} potential attacks ({rate:.1f}%) and {normal:,} normal packets.\n\n"
        if rate > 5:
            s += "The elevated attack rate requires immediate attention. Review firewall rules and investigate source IPs."
        else:
            s += "The security posture appears stable. Continue routine monitoring and keep systems patched."
        return s


# Singleton
_threat_intel_service = None

def get_llm_service():
    global _threat_intel_service
    if _threat_intel_service is None:
        _threat_intel_service = ThreatIntelligenceService()
    return _threat_intel_service

def get_threat_intel_service():
    return get_llm_service()