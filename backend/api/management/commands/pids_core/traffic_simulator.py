"""
PIDS - Traffic Simulator (v3 - Accurate Behavioural Signatures)
Generates test traffic with the canonical 31 feature names and REALISTIC
attack patterns that match the behavioural engine's detection logic.
"""
import random
import time
from colorama import Fore, Style


class TrafficSimulator:
    def __init__(self, stats_manager, ws_manager, db_model, pc_ip):
        self.stats = stats_manager
        self.ws = ws_manager
        self.db_model = db_model
        self.pc_ip = pc_ip
        self.llm_service = None

        # Known attack types the ML model can detect
        self.attack_types = [
            'Bot', 'DDOS attack-HOIC', 'DDoS attacks-LOIC-HTTP',
            'DoS attacks-SlowHTTPTest', 'DoS attacks-Hulk',
            'DoS attacks-GoldenEye', 'FTP-BruteForce', 'SSH-Bruteforce',
            'SQL Injection'
        ]

        # Zero-day scenarios with behaviour hints for feature generation
        self.suspicious_scenarios = [
            {'port': 4444, 'proto': 'TCP', 'behaviour': 'reverse_shell'},
            {'port': 5555, 'proto': 'TCP', 'behaviour': 'reverse_shell'},
            {'port': 6667, 'proto': 'TCP', 'behaviour': 'c2_beacon'},
            {'port': 9001, 'proto': 'TCP', 'behaviour': 'c2_beacon'},
            {'port': 8080, 'proto': 'TCP', 'behaviour': 'dos_flood'},
            {'port': 53,   'proto': 'UDP', 'behaviour': 'exfiltration'},
            {'port': 445,  'proto': 'TCP', 'behaviour': 'brute_force'},
            {'port': 3389, 'proto': 'TCP', 'behaviour': 'brute_force'},
            {'port': 1433, 'proto': 'TCP', 'behaviour': 'sql_injection'},
            {'port': 27017,'proto': 'TCP', 'behaviour': 'exfiltration'},
            {'port': 6379, 'proto': 'TCP', 'behaviour': 'dos_flood'},
            {'port': 2375, 'proto': 'TCP', 'behaviour': 'dos_flood'},
            {'port': 11211,'proto': 'TCP', 'behaviour': 'exfiltration'},
            {'port': 161,  'proto': 'UDP', 'behaviour': 'scan'},
        ]

        self.external_ips = ['8.8.8.8', '1.1.1.1', '142.250.185.78', '104.16.249.249']
        self.malicious_ips = ['45.155.205.233', '185.220.100.242', '5.188.86.172']
        self.suspicious_ips = ['91.234.56.78', '103.45.67.89', '178.90.12.34']

        self._init_llm()

    def _init_llm(self):
        try:
            from .llm_service import get_llm_service
            self.llm_service = get_llm_service()
            if self.llm_service and self.llm_service.is_available:
                print(f"{Fore.GREEN}✅ LLM Service ready for zero-day detection{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️ LLM Service not available: {e}{Style.RESET_ALL}")
            self.llm_service = None

    # =========================================================================
    # PACKET GENERATION
    # =========================================================================
    def generate_packet(self):
        rand = random.random()
        if rand < 0.15:
            return self._generate_known_attack()
        elif rand < 0.25:
            return self._generate_zero_day_attack()
        elif rand < 0.35:
            return self._generate_suspicious()
        elif rand < 0.45:
            return self._generate_low_confidence()
        else:
            return self._generate_normal()

    # =========================================================================
    # CORRECT 31-FEATURE GENERATOR (matches FeatureExtractor.SELECTED_FEATURES)
    # =========================================================================
    def _build_features(self, port, proto, behaviour='normal'):
        """Generate all 31 features with CORRECT names matching the ML/DL models
        and behavioural engine. Each behaviour type has a distinct signature."""

        if behaviour == 'dos_flood':
            # DoS/DDoS: extreme rate, large pkts, unidirectional, no handshake
            fwd_rate = random.uniform(5000, 60000)
            bwd_rate = 0
            fwd_mean = random.uniform(400, 1800)
            fwd_max = fwd_mean * random.uniform(1.1, 1.5)
            fwd_std = random.uniform(30, 600)
            bwd_max = 0
            bwd_std = 0
            duration = random.uniform(5000, 50000)  # very short burst
            iat_mean = random.uniform(50, 500)
            iat_std = random.uniform(10, 200)
            iat_min = random.uniform(10, 50)
            iat_max = random.uniform(500, 2000)
            ack = 0
            init_fwd_win = 0
            init_bwd_win = 0
            fwd_header = 0
            bwd_header = 0
            subflow_fwd = 0
            subflow_bwd = 0
            fwd_act = 0

        elif behaviour == 'c2_beacon':
            # C2: low bidirectional, small pkts, long duration, regular beacons
            fwd_rate = random.uniform(1, 30)
            bwd_rate = random.uniform(1, 20)
            fwd_mean = random.uniform(50, 180)
            fwd_max = fwd_mean * random.uniform(1.2, 2.0)
            fwd_std = random.uniform(5, 40)
            bwd_max = random.uniform(80, 400)
            bwd_std = random.uniform(10, 60)
            duration = random.uniform(10_000_000, 60_000_000)  # 10-60 seconds
            iat_mean = random.uniform(500_000, 3_000_000)  # regular long intervals
            iat_std = iat_mean * random.uniform(0.05, 0.25)  # very consistent
            iat_min = iat_mean * random.uniform(0.5, 0.8)
            iat_max = iat_mean * random.uniform(1.2, 1.8)
            ack = 1
            init_fwd_win = random.randint(8000, 65535)
            init_bwd_win = random.randint(8000, 65535)
            fwd_header = random.randint(100, 500)
            bwd_header = random.randint(50, 200)
            subflow_fwd = random.randint(10, 100)
            subflow_bwd = random.randint(5, 50)
            fwd_act = random.randint(5, 50)

        elif behaviour == 'brute_force':
            # Brute Force: moderate rate, small uniform pkts, auth ports
            fwd_rate = random.uniform(50, 2000)
            bwd_rate = random.uniform(10, 500)
            fwd_mean = random.uniform(60, 250)
            fwd_max = fwd_mean * random.uniform(1.0, 1.3)
            fwd_std = random.uniform(5, 40)  # very uniform
            bwd_max = random.uniform(40, 180)
            bwd_std = random.uniform(5, 30)
            duration = random.uniform(100_000, 2_000_000)
            iat_mean = random.uniform(1000, 50000)
            iat_std = iat_mean * random.uniform(0.1, 0.4)  # regular automated
            iat_min = random.uniform(100, 1000)
            iat_max = iat_mean * random.uniform(1.5, 3.0)
            ack = random.choice([0, 1])
            init_fwd_win = random.choice([0, random.randint(1000, 65535)])
            init_bwd_win = random.choice([0, random.randint(1000, 65535)])
            fwd_header = random.randint(40, 200)
            bwd_header = random.randint(20, 100)
            subflow_fwd = random.randint(15, 200)
            subflow_bwd = random.randint(5, 50)
            fwd_act = random.randint(5, 100)

        elif behaviour == 'exfiltration':
            # Data Exfiltration: large outbound, tiny inbound, sustained
            fwd_rate = random.uniform(20, 400)
            bwd_rate = random.uniform(0, 10)
            fwd_mean = random.uniform(900, 3000)
            fwd_max = fwd_mean * random.uniform(1.1, 1.5)
            fwd_std = random.uniform(100, 500)
            bwd_max = random.uniform(0, 150)
            bwd_std = random.uniform(0, 30)
            duration = random.uniform(2_000_000, 30_000_000)  # sustained
            iat_mean = random.uniform(10_000, 500_000)
            iat_std = random.uniform(50_000, 300_000)
            iat_min = random.uniform(1000, 10_000)
            iat_max = random.uniform(500_000, 2_000_000)
            ack = 1
            init_fwd_win = random.randint(10000, 65535)
            init_bwd_win = random.choice([0, random.randint(1000, 10000)])
            fwd_header = random.randint(200, 1000)
            bwd_header = random.randint(0, 100)
            subflow_fwd = random.randint(20, 200)
            subflow_bwd = random.randint(0, 10)
            fwd_act = random.randint(10, 100)

        elif behaviour == 'reverse_shell':
            # Reverse Shell: bidirectional, interactive timing, established
            fwd_rate = random.uniform(5, 80)
            bwd_rate = random.uniform(10, 120)  # more from C2
            fwd_mean = random.uniform(40, 200)  # small commands
            fwd_max = random.uniform(100, 500)
            fwd_std = random.uniform(30, 150)  # variable
            bwd_max = random.uniform(500, 5000)  # command outputs
            bwd_std = random.uniform(100, 1000)
            duration = random.uniform(5_000_000, 30_000_000)
            iat_mean = random.uniform(200_000, 2_000_000)  # human typing
            iat_std = random.uniform(500_000, 3_000_000)  # very variable
            iat_min = random.uniform(10_000, 100_000)
            iat_max = random.uniform(3_000_000, 10_000_000)
            ack = 1
            init_fwd_win = random.randint(8000, 65535)
            init_bwd_win = random.randint(8000, 65535)
            fwd_header = random.randint(100, 400)
            bwd_header = random.randint(150, 600)
            subflow_fwd = random.randint(10, 80)
            subflow_bwd = random.randint(15, 120)
            fwd_act = random.randint(5, 40)

        elif behaviour == 'sql_injection':
            # SQL Injection: large varied payloads to DB, small responses
            fwd_rate = random.uniform(10, 200)
            bwd_rate = random.uniform(5, 50)
            fwd_mean = random.uniform(500, 2000)
            fwd_max = random.uniform(1500, 5000)
            fwd_std = random.uniform(200, 800)  # high variance (different queries)
            bwd_max = random.uniform(100, 500)
            bwd_std = random.uniform(20, 100)
            duration = random.uniform(500_000, 5_000_000)
            iat_mean = random.uniform(10_000, 200_000)
            iat_std = random.uniform(50_000, 500_000)
            iat_min = random.uniform(1000, 10_000)
            iat_max = random.uniform(200_000, 1_000_000)
            ack = 1
            init_fwd_win = random.randint(10000, 65535)
            init_bwd_win = random.randint(5000, 30000)
            fwd_header = random.randint(100, 400)
            bwd_header = random.randint(40, 150)
            subflow_fwd = random.randint(10, 100)
            subflow_bwd = random.randint(5, 30)
            fwd_act = random.randint(5, 50)

        elif behaviour == 'scan':
            # Port Scanning: very short probes, tiny packets, no data
            fwd_rate = random.uniform(50, 500)
            bwd_rate = 0
            fwd_mean = random.uniform(40, 70)
            fwd_max = random.uniform(60, 80)
            fwd_std = random.uniform(2, 15)
            bwd_max = random.uniform(0, 60)
            bwd_std = 0
            duration = random.uniform(5000, 40000)  # very short
            iat_mean = random.uniform(500, 5000)
            iat_std = random.uniform(100, 2000)
            iat_min = random.uniform(50, 500)
            iat_max = random.uniform(5000, 20000)
            ack = 0
            init_fwd_win = random.randint(1000, 65535)
            init_bwd_win = 0
            fwd_header = 0
            bwd_header = 0
            subflow_fwd = random.randint(1, 3)
            subflow_bwd = 0
            fwd_act = 0

        else:
            # Normal traffic
            fwd_rate = random.uniform(1, 100)
            bwd_rate = random.uniform(1, 80)
            fwd_mean = random.uniform(100, 600)
            fwd_max = fwd_mean * random.uniform(1.2, 2.5)
            fwd_std = random.uniform(20, 200)
            bwd_max = random.uniform(100, 800)
            bwd_std = random.uniform(20, 200)
            duration = random.uniform(100_000, 10_000_000)
            iat_mean = random.uniform(10_000, 500_000)
            iat_std = random.uniform(5000, 300_000)
            iat_min = random.uniform(1000, 50_000)
            iat_max = random.uniform(100_000, 2_000_000)
            ack = 1 if proto == 'TCP' else 0
            init_fwd_win = random.randint(10000, 65535) if proto == 'TCP' else 65535
            init_bwd_win = random.randint(10000, 65535) if proto == 'TCP' else 65535
            fwd_header = random.randint(100, 500)
            bwd_header = random.randint(100, 500)
            subflow_fwd = random.randint(5, 50)
            subflow_bwd = random.randint(5, 50)
            fwd_act = random.randint(3, 30)

        dur_sec = duration / 1_000_000 if duration > 0 else 0.001
        fwd_iat_mean = iat_mean * random.uniform(0.8, 1.2)
        fwd_iat_std = iat_std * random.uniform(0.8, 1.2)
        bwd_iat_mean = iat_mean * random.uniform(0.8, 1.3)
        bwd_iat_tot = bwd_iat_mean * max(subflow_bwd, 1)

        # All 31 features (canonical schema). Newly-added features (vs the
        # legacy 31) are populated with sensible synthetic defaults that
        # preserve the per-behaviour signal for testing the engines.
        # Some behaviour branches above only define ``bwd_max``/``bwd_std``;
        # synthesise a mean from the max so the new packet-length stats
        # work regardless of which branch fired.
        bwd_mean_synth = (bwd_max * 0.7) if bwd_max else 0.0
        all_pkt_lens = [fwd_mean, bwd_mean_synth, fwd_max, bwd_max]
        # Strip zero-length placeholders so single-direction flows don't
        # bias the combined-length stats toward 0.
        nonzero_lens = [v for v in all_pkt_lens if v > 0] or [0.0]
        pkt_len_min  = float(min(nonzero_lens))
        pkt_len_max  = float(max(nonzero_lens))
        pkt_len_mean = float(sum(nonzero_lens) / len(nonzero_lens))
        pkt_len_std  = float((max(nonzero_lens) - min(nonzero_lens)) / 4)
        # Flag-count stand-ins driven by the synthesised behaviour:
        # high-rate floods see lots of SYN; established TCP gets ACK.
        is_flood = subflow_fwd > 100 or fwd_rate > 1000
        syn_cnt = int(subflow_fwd * 0.9) if is_flood else int(min(subflow_fwd, 3))
        return {
            # Volume / rate
            'Dst Port':          port,
            'Flow Duration':     duration,
            'Tot Fwd Pkts':      subflow_fwd,
            'Tot Bwd Pkts':      subflow_bwd,
            'TotLen Fwd Pkts':   int(fwd_mean * subflow_fwd),
            'TotLen Bwd Pkts':   int(bwd_mean_synth * subflow_bwd),
            'Subflow Fwd Pkts':  subflow_fwd,
            'Subflow Bwd Pkts':  subflow_bwd,
            'Fwd Pkts/s':        fwd_rate,
            'Bwd Pkts/s':        bwd_rate,
            'Down/Up Ratio':     (subflow_bwd / subflow_fwd) if subflow_fwd > 0 else 0.0,

            # Inter-arrival times
            'Flow IAT Mean':     iat_mean,
            'Flow IAT Std':      iat_std,
            'Flow IAT Max':      iat_max,
            'Flow IAT Min':      iat_min,
            'Fwd IAT Mean':      fwd_iat_mean,
            'Fwd IAT Std':       fwd_iat_std,
            'Fwd IAT Max':       iat_max * random.uniform(0.9, 1.1),
            'Fwd IAT Min':       iat_min * random.uniform(0.9, 1.1),
            'Fwd IAT Tot':       fwd_iat_mean * max(subflow_fwd, 1),
            'Bwd IAT Mean':      bwd_iat_mean,
            'Bwd IAT Min':       iat_min * random.uniform(0.8, 1.2),
            'Bwd IAT Tot':       bwd_iat_tot,

            # Per-direction packet length stats
            'Fwd Pkt Len Mean':  fwd_mean,
            'Fwd Pkt Len Std':   fwd_std,
            'Fwd Pkt Len Max':   fwd_max,
            'Bwd Pkt Len Std':   bwd_std,
            'Bwd Pkt Len Max':   bwd_max,

            # Combined packet length stats (NEW — 31-feature schema)
            'Pkt Len Min':       pkt_len_min,
            'Pkt Len Max':       pkt_len_max,
            'Pkt Len Mean':      pkt_len_mean,
            'Pkt Len Std':       pkt_len_std,

            # Header / segment sizing
            'Fwd Header Len':    fwd_header,
            'Bwd Header Len':    bwd_header,
            'Fwd Act Data Pkts': fwd_act,
            'Fwd Seg Size Min':  20 if proto == 'TCP' else 8,

            # TCP flags — cumulative counts (NEW — 31-feature schema)
            'FIN Flag Cnt':      1 if not is_flood and proto == 'TCP' else 0,
            'SYN Flag Cnt':      syn_cnt,
            'RST Flag Cnt':      int(subflow_fwd * 0.3) if is_flood else 0,
            'PSH Flag Cnt':      int(subflow_fwd * 0.2) if proto == 'TCP' else 0,
            'URG Flag Cnt':      0,
            'CWE Flag Count':    0,
            'ECE Flag Cnt':      0,
            'ACK Flag Cnt':      ack,
            'Fwd PSH Flags':     int(subflow_fwd * 0.15) if proto == 'TCP' else 0,
            'Bwd PSH Flags':     int(subflow_bwd * 0.10) if proto == 'TCP' else 0,
            'Fwd URG Flags':     0,

            # TCP window
            'Init Fwd Win Byts': init_fwd_win,
            'Init Bwd Win Byts': init_bwd_win,

            # Active / idle (NEW — 31-feature schema)
            'Active Mean':       random.uniform(0.5, 5.0),
            'Active Std':        random.uniform(0.0, 1.0),
            'Idle Mean':         random.uniform(0.0, 10.0) if not is_flood else 0.0,
            'Idle Std':          random.uniform(0.0, 2.0),
        }

    # =========================================================================
    # TRAFFIC GENERATORS
    # =========================================================================
    def _generate_known_attack(self):
        src_ip = random.choice(self.malicious_ips)
        dst_ip = self.pc_ip
        pred = random.choice(self.attack_types)
        conf = random.uniform(0.85, 0.99)
        proto = "TCP"
        port = random.choice([80, 443, 22, 21, 3389])
        status = 'Attack'
        self._log_traffic(src_ip, dst_ip, port, proto, pred, conf, status)

    def _generate_zero_day_attack(self):
        scenario = random.choice(self.suspicious_scenarios)
        src_ip = random.choice(self.suspicious_ips)
        dst_ip = self.pc_ip
        proto = scenario['proto']
        port = scenario['port']
        ml_conf = random.uniform(0.40, 0.65)
        status = 'Suspicious'
        ml_pred = "Unknown"
        llm_used = False

        features = self._build_features(port, proto, scenario['behaviour'])

        if self.llm_service and self.llm_service.is_available:
            print(f"{Fore.MAGENTA}🔮 Analyzing suspicious behavior with LLM...{Style.RESET_ALL}")
            traffic_data = {
                'src_ip': src_ip, 'dst_ip': dst_ip,
                'src_port': random.randint(40000, 60000), 'dst_port': port,
                'protocol': proto, 'ml_prediction': 'Unknown', 'ml_confidence': ml_conf
            }
            try:
                result = self.llm_service.analyze_zero_day(traffic_data, features)
                if result.get('success'):
                    llm_used = True
                    attack_category = result.get('attack_category', 'Unknown Threat')
                    llm_conf = result.get('confidence', 0.7)
                    reasoning = result.get('reasoning', '')
                    if result.get('is_zero_day') or result.get('is_suspicious'):
                        status = 'Attack'
                        ml_pred = f"LLM-Detected: {attack_category}"
                        ml_conf = llm_conf
                        print(f"{Fore.MAGENTA}🔮 LLM Detection: {attack_category} ({llm_conf:.1%}){Style.RESET_ALL}")
                        if reasoning:
                            print(f"{Fore.MAGENTA}   💡 Reason: {reasoning[:100]}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.GREEN}✅ LLM: Traffic appears benign{Style.RESET_ALL}")
                        status = 'Normal'
                        ml_pred = 'Normal'
                        ml_conf = 0.85
            except Exception as e:
                print(f"{Fore.RED}LLM Error: {e}{Style.RESET_ALL}")

        self._log_traffic(src_ip, dst_ip, port, proto, ml_pred, ml_conf, status, llm_used, features)

    def _generate_suspicious(self):
        src_ip = random.choice(self.external_ips)
        dst_ip = self.pc_ip
        proto = random.choice(["UDP", "TCP"])
        port = random.randint(1024, 9999)
        ml_pred = 'Suspicious'
        ml_conf = random.uniform(0.55, 0.75)
        status = 'Suspicious'
        llm_used = False

        # Generate ambiguous features (could go either way)
        behaviour = random.choice(['normal', 'c2_beacon', 'scan'])
        features = self._build_features(port, proto, behaviour)

        if self.llm_service and self.llm_service.is_available:
            traffic_data = {
                'src_ip': src_ip, 'dst_ip': dst_ip,
                'src_port': random.randint(40000, 60000), 'dst_port': port,
                'protocol': proto, 'ml_prediction': ml_pred, 'ml_confidence': ml_conf
            }
            try:
                result = self.llm_service.analyze_zero_day(traffic_data, features)
                if result.get('success'):
                    llm_used = True
                    is_suspicious = result.get('is_suspicious', False)
                    attack_category = result.get('attack_category', '')
                    llm_conf = result.get('confidence', 0.7)
                    if is_suspicious and attack_category.lower() not in ['benign', 'normal', 'none', '']:
                        status = 'Attack'
                        ml_pred = f"LLM-Detected: {attack_category}"
                        ml_conf = llm_conf
                        print(f"{Fore.RED}🔮 LLM → ATTACK: {attack_category}{Style.RESET_ALL}")
                    else:
                        status = 'Normal'
                        ml_pred = 'Normal'
                        ml_conf = 0.88
                        print(f"{Fore.GREEN}🔮 LLM → NORMAL (Cleared){Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}⚠️ LLM error: {e}{Style.RESET_ALL}")

        self._log_traffic(src_ip, dst_ip, port, proto, ml_pred, ml_conf, status, llm_used, features)

    def _generate_low_confidence(self):
        src_ip = random.choice(self.external_ips + self.suspicious_ips)
        dst_ip = self.pc_ip
        proto = random.choice(["TCP", "UDP"])
        port = random.choice([8080, 8443, 3000, 5000, 9000, 10000])
        ml_pred = random.choice(['Normal', 'Attack', 'Bot'])
        ml_conf = random.uniform(0.50, 0.74)
        ml_status = 'Attack' if ml_pred != 'Normal' else 'Normal'
        llm_used = False

        behaviour = random.choice(['normal', 'dos_flood', 'brute_force'])
        features = self._build_features(port, proto, behaviour)

        if self.llm_service and self.llm_service.is_available:
            print(f"{Fore.MAGENTA}🔮 LLM analyzing low-confidence traffic ({ml_conf:.1%})...{Style.RESET_ALL}")
            traffic_data = {
                'src_ip': src_ip, 'dst_ip': dst_ip,
                'src_port': random.randint(40000, 60000), 'dst_port': port,
                'protocol': proto, 'ml_prediction': ml_pred, 'ml_confidence': ml_conf
            }
            try:
                result = self.llm_service.analyze_zero_day(traffic_data, features)
                if result.get('success'):
                    llm_used = True
                    is_suspicious = result.get('is_suspicious', False)
                    attack_category = result.get('attack_category', '')
                    llm_conf = result.get('confidence', 0.7)
                    if is_suspicious and attack_category.lower() not in ['benign', 'normal', 'none', '']:
                        ml_status = 'Attack'
                        ml_pred = f"LLM-Detected: {attack_category}"
                        ml_conf = llm_conf
                        print(f"{Fore.RED}🔮 LLM Override: ATTACK → {attack_category}{Style.RESET_ALL}")
                    else:
                        ml_status = 'Normal'
                        ml_pred = 'Normal'
                        ml_conf = max(llm_conf, 0.85)
                        print(f"{Fore.GREEN}🔮 LLM Override: NORMAL{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}⚠️ LLM error: {e}{Style.RESET_ALL}")

        self._log_traffic(src_ip, dst_ip, port, proto, ml_pred, ml_conf, ml_status, llm_used, features)

    def _generate_normal(self):
        src_ip = self.pc_ip
        dst_ip = random.choice(self.external_ips)
        pred = 'Normal'
        conf = random.uniform(0.90, 0.99)
        proto = "TCP"
        port = 443
        status = 'Normal'
        features = self._build_features(port, proto, 'normal')
        self._log_traffic(src_ip, dst_ip, port, proto, pred, conf, status, features=features)

    # =========================================================================
    # LOGGING
    # =========================================================================
    def _log_traffic(self, src_ip, dst_ip, port, proto, pred, conf, status,
                     llm_used=False, features=None):
        self.stats.update(status)

        if status == 'Attack':
            color, icon = Fore.RED, "🚨"
        elif status == 'Suspicious':
            color, icon = Fore.YELLOW, "⚠️"
        else:
            color, icon = Fore.GREEN, "✅"

        llm_tag = " [LLM]" if llm_used else ""
        print(f"{color}{icon} [TEST] {src_ip} -> {dst_ip}:{port} | {proto} | "
              f"{pred} ({conf:.1%}) [{status}]{llm_tag}{Style.RESET_ALL}")

        # Use provided features or generate normal ones
        if features is None:
            features = self._build_features(port, proto, 'normal')

        if self.db_model:
            try:
                log = self.db_model.objects.create(
                    src_ip=src_ip, dst_ip=dst_ip,
                    src_port=random.randint(40000, 60000), dst_port=port,
                    protocol=proto, length=random.randint(60, 1500),
                    prediction=pred, confidence=float(conf), status=status,
                    attack_type=pred if status in ['Attack', 'Suspicious'] else None,
                    features=features,
                    llm_analyzed=llm_used,
                    is_zero_day='LLM-Detected' in pred if pred else False,
                    involves_local_pc=True
                )
                self.ws.send_update(log)
            except Exception as e:
                print(f"{Fore.YELLOW}⚠️ [TEST] DB Error: {e}{Style.RESET_ALL}")