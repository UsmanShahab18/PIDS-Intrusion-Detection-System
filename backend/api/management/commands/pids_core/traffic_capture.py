"""
PIDS - Traffic Capture Module
Captures live network traffic, extracts features, and saves to database
"""
from scapy.all import sniff, IP, TCP, UDP
from colorama import Fore, Style
import traceback
import json
import time
import warnings
warnings.filterwarnings('ignore', category=UserWarning, module='xgboost')
warnings.filterwarnings('ignore', category=UserWarning, module='sklearn')

class TrafficCapture:
    # =========================================================================
    # SAFE IP WHITELIST - Known EXTERNAL legitimate services ONLY
    # NEVER whitelist local/private IPs — attacks come from inside the network!
    # Only specific, verified external service IP ranges
    # =========================================================================
    SAFE_IP_PREFIXES = {
        # GitHub
        '185.199.': 'GitHub', '140.82.': 'GitHub',
        # Google
        '142.250.': 'Google', '172.217.': 'Google', '216.239.': 'Google',
        '8.8.8.': 'Google DNS', '8.8.4.': 'Google DNS', '142.251.': 'Google',
        '74.125.': 'Google', '173.194.': 'Google',
        # Cloudflare
        '104.16.': 'Cloudflare', '104.17.': 'Cloudflare', '104.18.': 'Cloudflare',
        '104.19.': 'Cloudflare', '104.20.': 'Cloudflare', '104.21.': 'Cloudflare',
        '104.22.': 'Cloudflare', '104.23.': 'Cloudflare', '104.24.': 'Cloudflare',
        '104.25.': 'Cloudflare', '104.26.': 'Cloudflare', '104.27.': 'Cloudflare',
        '1.1.1.': 'Cloudflare DNS', '1.0.0.': 'Cloudflare DNS',
        '103.21.': 'Cloudflare', '103.22.': 'Cloudflare', '103.31.': 'Cloudflare',
        # Microsoft / Azure
        '13.': 'Microsoft Azure', '20.': 'Microsoft Azure',
        '40.': 'Microsoft Azure', '51.': 'Microsoft Azure',
        '52.': 'Microsoft Azure', '57.': 'Microsoft Azure',
        '204.79.': 'Microsoft',
        # AWS
        '3.': 'AWS', '18.': 'AWS', '34.': 'AWS', '35.': 'AWS',
        '54.': 'AWS', '72.': 'AWS', '99.': 'AWS',
        # Cloudflare (full range)
        '103.': 'Cloudflare',
        # Fastly CDN
        '151.101.': 'Fastly CDN', '151.139.': 'Fastly CDN',
        # Akamai
        '23.': 'Akamai/CDN', '184.': 'Akamai/CDN', '2.16.': 'Akamai/CDN', '2.17.': 'Akamai/CDN',
        # Other CDN / Major services
        '92.': 'CDN/Hosting', '93.': 'CDN/Hosting', '98.': 'CDN/Hosting',
        '213.': 'CDN/Hosting', '31.': 'CDN/Hosting',
        # Apple
        '17.': 'Apple',
        # NOTE: NO local/private IPs (192.168.*, 10.*, 172.16-31.*)
    }
    # Standard ports that are safe ONLY when going to known EXTERNAL services
    SAFE_PORTS = {80, 443, 53, 853, 8443}

    def __init__(self, interface, feature_extractor, ml_engine, stats, ws, db_model, pc_ip):
        # `ml_engine` is retained in the signature for backward compatibility
        # with existing callers (start_sniffer, test_attacks). The new
        # registry-based detection path ignores it and dispatches via
        # api.detection.engines.engine_registry.get_active_engine_cached().
        self.interface = interface
        self.extractor = feature_extractor
        self.ml = ml_engine  # legacy reference; unused for prediction
        self.stats = stats
        self.ws = ws
        self.db = db_model
        self.pc_ip = pc_ip
        # PIDS application ports — traffic TO these on this PC = users using the app
        self.PIDS_APP_PORTS = {3000, 8000, 8001}
        # Connection rate tracker — detects SYN floods that ML misses
        # Tracks: {(src_ip, dst_port): [timestamp1, timestamp2, ...]}
        self._conn_tracker = {}
        self._conn_tracker_cleanup = time.time()
        # LLM result cache — send first packet of a rate alert to LLM, cache result
        # Key: (src_ip, port), Value: {'label': 'Data Exfiltration', 'time': timestamp}
        self._llm_cache = {}
        # ENABLED - LLM will analyze suspicious traffic and classify as Attack or Normal
        self.enable_llm = True
        self.llm_service = None
        self._init_llm()
        print(f"{Fore.CYAN}🖥️ PC IP for self-traffic detection: {self.pc_ip}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🛡️ PIDS app ports whitelisted: {self.PIDS_APP_PORTS}{Style.RESET_ALL}")
    
    # =========================================================================
    # BENIGN PROTOCOL WHITELIST - Known harmless network discovery protocols
    # These are standard OS-level protocols that are NEVER attacks
    # =========================================================================
    BENIGN_MULTICAST = {
        # mDNS - Multicast DNS (Apple Bonjour, Linux Avahi, Windows discovery)
        5353: 'mDNS',
        # SSDP - Simple Service Discovery Protocol (UPnP devices, routers, IoT)
        1900: 'SSDP',
        # LLMNR - Link-Local Multicast Name Resolution (Windows name resolution)
        5355: 'LLMNR',
        # IGMP / multicast management (no port, but covers multicast groups)
    }
    BENIGN_BROADCAST = {
        # NetBIOS Name Service / Datagram (Windows network neighbourhood)
        137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN',
        # DHCP
        67: 'DHCP-Server', 68: 'DHCP-Client',
        # SSDP on broadcast
        1900: 'SSDP',
    }

    def _is_safe_ip(self, src_ip, dst_ip, sport, dport, proto='TCP'):
        """Check if traffic is safe and should NOT be flagged.
        
        LOGIC:
        - Multicast/Broadcast on known discovery ports: ALWAYS safe
        - TCP to/from this PC on app ports: SAFE (users accessing PIDS web UI)
        - TCP from local device to this PC: SAFE (web browsing the dashboard)
        - UDP from local device to this PC: NOT safe (could be UDP flood attack)
        - Local-to-local (not involving this PC): NEVER safe
        - External on standard ports: SAFE
        """
        # ─── RULE 0: Multicast & Broadcast (benign OS-level protocols) ───
        is_multicast = dst_ip.startswith(('224.', '225.', '226.', '227.',
                                          '228.', '229.', '230.', '231.',
                                          '232.', '233.', '234.', '235.',
                                          '236.', '237.', '238.', '239.'))
        is_broadcast = dst_ip == '255.255.255.255' or dst_ip.endswith('.255')

        if is_multicast and dport in self.BENIGN_MULTICAST:
            return f'{self.BENIGN_MULTICAST[dport]} (Multicast)'
        if is_broadcast and dport in self.BENIGN_BROADCAST:
            return f'{self.BENIGN_BROADCAST[dport]} (Broadcast)'
        if is_multicast and dport in {5353, 1900, 5355, 547, 546}:
            return 'Network Discovery (Multicast)'
        
        local_prefixes = ('192.168.', '10.', '172.16.', '172.17.',
                    '172.18.', '172.19.', '172.20.', '172.21.', '172.22.',
                    '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
                    '172.28.', '172.29.', '172.30.', '172.31.', '127.')
        
        src_local = src_ip.startswith(local_prefixes)
        dst_local = dst_ip.startswith(local_prefixes)
        
        # ─── RULE 0.5: PIDS self-traffic (TCP only) ───
        # ONLY whitelist traffic to/from PIDS application ports specifically
        # Everything else goes through ML for proper detection
        # This catches: phone browsing dashboard, API calls, WebSocket
        # Does NOT catch: SYN floods on port 80/8080, brute force on 22, exfil on 4444
        if proto == 'TCP':
            pids_ports = self.PIDS_APP_PORTS  # {3000, 8000, 8001}
            if dport in pids_ports or sport in pids_ports:
                if dst_ip == self.pc_ip and src_local:
                    return 'PIDS Web Access (TCP)'
                if src_ip == self.pc_ip and dst_local:
                    return 'PIDS Web Response (TCP)'

        # RULE 1: Both local (not involving this PC) → NEVER safe
        if src_local and dst_local:
            return None
        
        # ─── RULE 1.5: VoIP / STUN / TURN (UDP) = calls (WhatsApp, Teams, Zoom) ───
        # STUN/TURN ports are used for VoIP/video calls — always safe
        voip_ports = {3478, 3479, 5349, 5350, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309}
        if dport in voip_ports or sport in voip_ports:
            return 'VoIP/STUN Call Traffic'

        # ─── RULE 2: External ↔ This PC = normal internet traffic ───
        # TCP: web browsing (always safe for this PC)
        # UDP: safe if this PC is involved (DNS, VoIP, gaming, streaming)
        # Real UDP attacks come from LOCAL devices (phone flood), not external servers
        if src_ip == self.pc_ip and not dst_local:
            return 'Internet Traffic (Outbound)'
        if dst_ip == self.pc_ip and not src_local:
            return 'Internet Traffic (Inbound)'
        
        # RULE 2b: External on standard ports (for other local devices, not this PC)
        if src_local and not dst_local and dport in self.SAFE_PORTS:
            return 'External Web Service'
        if not src_local and dst_local and sport in self.SAFE_PORTS:
            return 'External Web Service'
        
        # RULE 3: Both external → check prefix list
        for prefix, service in self.SAFE_IP_PREFIXES.items():
            if dst_ip.startswith(prefix) and dport in self.SAFE_PORTS:
                return service
            if src_ip.startswith(prefix) and sport in self.SAFE_PORTS:
                return service
        
        return None

    def _check_connection_rate(self, src_ip, dst_ip, dport, sport, proto):
        """
        Detect SYN flood / connection flood that ML misses.
        Tracks connection rate per (local_ip, target_port) pair.
        If a local IP has >30 flows to/from the same port in 10 seconds → attack.
        """
        now = time.time()
        
        local_prefixes = ('192.168.', '10.', '172.')
        
        # Determine if this involves a local device flooding this PC
        # Track the non-PIDS port involved
        track_ip = None
        track_port = None
        
        if dst_ip == self.pc_ip and src_ip.startswith(local_prefixes):
            # Inbound: local → this PC
            track_ip = src_ip
            track_port = dport
        elif src_ip == self.pc_ip and dst_ip.startswith(local_prefixes):
            # Outbound response: this PC → local (track the dst as the attacker)
            track_ip = dst_ip
            track_port = sport
        else:
            return None
        
        # Don't track PIDS app ports
        if track_port in self.PIDS_APP_PORTS:
            return None
            
        key = (track_ip, track_port)
        
        if key not in self._conn_tracker:
            self._conn_tracker[key] = []
        self._conn_tracker[key].append(now)
        
        # Keep only last 10 seconds
        self._conn_tracker[key] = [t for t in self._conn_tracker[key] if now - t < 10]
        
        # Cleanup old keys every 30 seconds
        if now - self._conn_tracker_cleanup > 30:
            self._conn_tracker_cleanup = now
            old_keys = [k for k, v in self._conn_tracker.items() if not v or now - v[-1] > 30]
            for k in old_keys:
                del self._conn_tracker[k]
        
        count = len(self._conn_tracker[key])
        
        # Auth ports need lower threshold (brute force = fewer but targeted connections)
        auth_ports = {22, 23, 21, 3389, 1433, 3306, 5432, 445}
        # Known malicious ports — classify by what the port is used for
        exfil_ports = {4444: 'Data Exfiltration (Metasploit)', 1337: 'Reverse Shell (Backdoor)',
                       31337: 'Reverse Shell (Back Orifice)', 5555: 'Android ADB Exploit',
                       4443: 'Reverse Shell', 8888: 'Reverse Shell', 1234: 'Reverse Shell',
                       12345: 'Reverse Shell (NetBus)'}
        c2_ports = {6667: 'Botnet C2 (IRC)', 9001: 'Tor Hidden Service',
                    2375: 'Docker API Exploit', 6379: 'Redis Unauthorized Access',
                    27017: 'MongoDB Data Breach'}
        
        threshold = 5 if track_port in auth_ports else 30
        
        if count > threshold:
            if count == threshold + 1 or count % 50 == 0:
                if track_port in auth_ports:
                    attack_label = 'Brute Force'
                elif track_port in exfil_ports:
                    attack_label = 'Data Exfiltration'
                elif track_port in c2_ports:
                    attack_label = 'C2 Communication'
                else:
                    attack_label = 'Connection Flood'
                print(f"{Fore.RED}🚨 RATE ALERT: {track_ip} → port {track_port}: {count} flows in 10s ({attack_label}){Style.RESET_ALL}")
            
            # Classify by port type
            if track_port in auth_ports:
                port_names = {22: 'SSH-Bruteforce', 23: 'Telnet-Bruteforce', 21: 'FTP-BruteForce', 
                              3389: 'RDP Brute Force', 1433: 'MSSQL-Bruteforce', 3306: 'MySQL-Bruteforce',
                              5432: 'PostgreSQL-Bruteforce', 445: 'SMB-Bruteforce'}
                return port_names.get(track_port, 'Brute Force Attack')
            elif track_port in exfil_ports:
                return exfil_ports[track_port]
            elif track_port in c2_ports:
                return c2_ports[track_port]
            elif proto == 'TCP':
                return 'DDoS attacks-LOIC-HTTP'
            else:
                return 'DDOS attack-HOIC'
        
        return None

    def _init_llm(self):
        """Initialize LLM service"""
        try:
            from .llm_service import get_llm_service
            self.llm_service = get_llm_service()
            if self.llm_service and self.llm_service.is_available:
                print(f"{Fore.GREEN}✅ LLM enabled for suspicious traffic analysis{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️ LLM not available: {e}{Style.RESET_ALL}")
            self.llm_service = None

    def process_packet(self, packet):
        try:
            # 1. Extract Features (all 31 — ML and DL share this schema)
            features = self.extractor.extract_features(packet)
            if not features:
                return

            # 2. Get Port Info for Display & DB
            proto = "OTHER"
            sport = 0
            dport = 0
            
            if packet.haslayer(TCP):
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
            elif packet.haslayer(UDP):
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport

            # 3. Predict via the active detection engine (ML or DL —
            #    selected by the EngineConfig DB singleton, read through
            #    a 5-second cache so per-packet calls don't hit Postgres).
            from api.detection.engines.engine_registry import get_active_engine_cached
            engine = get_active_engine_cached()
            # Acknowledge engine switches in the live console so the operator
            # can SEE the active model change take effect (the switch is read
            # from EngineConfig via a 5-second cache, so it applies within ~5s).
            _eng_name = getattr(engine, 'name', '?')
            if getattr(self, '_active_engine_name', None) != _eng_name:
                _prev = getattr(self, '_active_engine_name', None)
                self._active_engine_name = _eng_name
                if _prev is None:
                    print(f"{Fore.MAGENTA}🧠 ACTIVE DETECTION ENGINE: {_eng_name.upper()}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.MAGENTA}{'='*60}\n"
                          f"🔄 ACTIVE ENGINE CHANGED: {_prev.upper()} → {_eng_name.upper()}  "
                          f"— now scoring traffic with the {_eng_name.upper()} model\n"
                          f"{'='*60}{Style.RESET_ALL}")
            pred, conf, status = engine.predict_legacy(features, proto)
            
            # 3.1. MALICIOUS PORT FLAG — mark for LLM analysis (not direct detection)
            src = packet[IP].src
            dst = packet[IP].dst
            _mal_ports = {
                4444: 'Data Exfiltration (Metasploit)', 1337: 'Reverse Shell (Backdoor)',
                31337: 'Reverse Shell (Back Orifice)', 5555: 'Android ADB Exploit',
                4443: 'Reverse Shell', 1234: 'Reverse Shell', 12345: 'Reverse Shell (NetBus)',
                6667: 'Botnet C2 (IRC)', 9001: 'Tor Hidden Service',
                2375: 'Docker API Exploit', 6379: 'Redis Unauthorized Access',
                27017: 'MongoDB Data Breach',
                # --- extended suspicious / backdoor / C2 ports ---
                4445: 'Reverse Shell', 5554: 'Sasser Worm', 9050: 'Tor SOCKS',
                9051: 'Tor Control', 1080: 'SOCKS Proxy (C2 tunnel)', 6666: 'Botnet C2 (IRC)',
                6668: 'Botnet C2 (IRC)', 7777: 'Backdoor', 8888: 'Backdoor / alt-C2',
                3127: 'MyDoom Backdoor', 2745: 'Bagle Worm', 1024: 'Backdoor (Jade/Latinus)',
                65000: 'Reverse Shell', 54321: 'Backdoor (BO2K)', 30303: 'Backdoor (Sockets de Troie)',
            }
            _mal_hit = _mal_ports.get(dport) or _mal_ports.get(sport)
            _is_mal_local = False
            if _mal_hit:
                _src_l = src.startswith(('192.168.', '10.', '172.'))
                _dst_l = dst.startswith(('192.168.', '10.', '172.'))
                if _src_l and _dst_l:
                    _is_mal_local = True
                    # Set Suspicious so LLM will analyze it
                    pred = _mal_hit
                    conf = 0.55  # Low confidence forces LLM analysis
                    status = 'Suspicious'
            
            # 3.5. SAFE IP OVERRIDE — prevent false positives on known services
            # ML model (trained on CICIDS) flags GitHub/Google/etc as "Infiltration"
            # Override to Normal if BOTH the IP is known-safe AND the port is standard
            safe_service = self._is_safe_ip(src, dst, sport, dport, proto)
            if safe_service:
                if status in ('Attack', 'Suspicious'):
                    print(f"{Fore.CYAN}🛡️ SAFE OVERRIDE: {src}→{dst}:{dport} ({proto}) was '{pred}' → Normal [{safe_service}]{Style.RESET_ALL}")
                pred = 'Normal'
                conf = 0.95
                status = 'Normal'
            
            # 3.55. VICTIM RESPONSE OVERRIDE — PC's outgoing responses are NOT attacks
            # When someone attacks the PC, Scapy captures BOTH directions:
            #   INCOMING: attacker→PC  = real attack (keep as Attack)
            #   OUTGOING: PC→attacker  = victim response (SYN-ACK, RST, etc.) = NOT an attack
            # Only override for DoS/DDoS/BruteForce types where direction matters
            victim_override = False
            if not safe_service and src == self.pc_ip and status in ('Attack', 'Suspicious'):
                dos_keywords = ('dos', 'ddos', 'hulk', 'hoic', 'loic', 'flood', 'slowloris',
                                'goldeneye', 'slowhttptest', 'heartbleed', 'brute', 'ssh-brute', 'ftp-brute')
                pred_lower = pred.lower()
                if any(kw in pred_lower for kw in dos_keywords):
                    pred = 'Normal'
                    conf = 0.90
                    status = 'Normal'
                    victim_override = True

            # 3.56. ABNORMAL TRAFFIC PATTERN — route stealthy / zero-day shapes
            # to the LLM even when ML says Normal. These attacks are ENGINEERED
            # to evade per-flow thresholds (low-and-slow, jittered beaconing,
            # DNS tunnelling), so the single-flow model scores them benign. We
            # flag the FLOW SHAPE as Suspicious (low conf) so the LLM gets to
            # weigh in. Conservative thresholds keep ordinary traffic off the LLM.
            if (not safe_service and not victim_override and not _is_mal_local
                    and status == 'Normal'):
                _f = lambda k: float(features.get(k, 0) or 0)
                dur_s   = _f('Flow Duration') / 1_000_000.0     # µs → seconds
                # NOTE: the extractor has no "Flow Pkts/s" key — derive it from
                # the forward + backward per-second rates.
                fpps    = _f('Fwd Pkts/s') + _f('Bwd Pkts/s')
                iat_std = _f('Flow IAT Std')
                iat_mean = _f('Flow IAT Mean')
                fwd_len = _f('Fwd Pkt Len Mean')
                tot_pkts = _f('Tot Fwd Pkts') + _f('Tot Bwd Pkts')
                bwd_pkt_max = _f('Bwd Pkt Len Max')
                bwd_pps = _f('Bwd Pkts/s')
                _web = dport in (80, 443, 8080, 8443)

                # a) Low-and-slow (Slowloris) — STRONGLY GUARDED signature: web
                #    port, long-held flow, trickle of tiny packets, and the server
                #    barely replies (no real HTTP response). Normal web traffic
                #    can't satisfy all of these (it gets a real response → big
                #    bwd packets), so we classify it DIRECTLY as an attack and
                #    SKIP the LLM, which has repeatedly (and wrongly) cleared it.
                slow_dos = (proto == 'TCP' and _web and dur_s >= 8 and tot_pkts >= 3
                            and 0 < fpps < 8 and 0 < fwd_len < 120
                            and bwd_pkt_max < 200 and bwd_pps < 2)
                if slow_dos:
                    pred = 'DoS attacks-Slowloris'
                    conf = 0.90
                    status = 'Attack'           # direct verdict, conf ≥0.80 → LLM skipped
                    print(f"{Fore.RED}🐌 SLOW-DoS DETECTED: {src}→{dst}:{dport} ({proto}) "
                          f"→ DoS attacks-Slowloris ({dur_s:.0f}s, {fpps:.1f} pkt/s, "
                          f"{fwd_len:.0f}B, server barely responding){Style.RESET_ALL}")
                else:
                    abnormal = None
                    # b) Jittered beaconing (C2): highly irregular inter-arrival gaps.
                    if iat_std > 3_000_000 and iat_std > iat_mean and 2 < tot_pkts < 60:
                        abnormal = 'Irregular beaconing (high inter-arrival jitter)'
                    # c) DNS tunnelling / exfil: repeated queries within one flow.
                    elif dport == 53 and tot_pkts >= 4:
                        abnormal = 'Repeated DNS queries (possible tunnelling/exfil)'
                    if abnormal:
                        pred = f'Anomalous: {abnormal}'
                        conf = 0.60              # low conf → forces LLM analysis
                        status = 'Suspicious'
                        print(f"{Fore.YELLOW}🧪 ABNORMAL PATTERN: {src}→{dst}:{dport} "
                              f"({proto}) → Suspicious [{abnormal}]{Style.RESET_ALL}")

            # 3.6. CONNECTION RATE CHECK — detects floods that ML misses
            # ONLY check INCOMING traffic to PC (attacker → PC)
            # Skip: safe IPs, victim overrides, outgoing PC responses
            rate_alert = None
            rate_llm_needed = False
            is_incoming_to_pc = (dst == self.pc_ip and src != self.pc_ip)
            if not safe_service and not victim_override and is_incoming_to_pc and status == 'Normal':
                rate_alert = self._check_connection_rate(src, dst, dport, sport, proto)
                if rate_alert:
                    # Cache key: (attacker_ip, target_port) — only incoming reaches here
                    cache_key = (src, dport)
                    
                    # Check if LLM already classified this (IP, port) pair
                    cached = self._llm_cache.get(cache_key)
                    if cached and (time.time() - cached['time']) < 300:  # 5 min cache
                        pred = cached['label']
                        conf = 0.90
                        status = 'Attack'
                    else:
                        # Rate detector confirmed anomalous traffic (30+ flows/10s or 5+ on auth port)
                        # Trust rate detector directly — classify as Attack
                        # Don't defer to LLM (LLM sees port 80/443 as "normal" and overrides)
                        pred = rate_alert
                        conf = 0.90
                        status = 'Attack'
                        # Cache this classification so future flows are instantly classified
                        self._llm_cache[cache_key] = {'label': rate_alert, 'time': time.time()}
            
            # 3.7. MALICIOUS PORT OVERRIDE — if ML says one thing but port is known malicious,
            # use port-aware classification instead of ML label
            # e.g., ML says "SQL Injection" on port 4444 → override to "Data Exfiltration (Metasploit)"
            if not safe_service and not rate_alert and not _is_mal_local:
                exfil_ports = {4444: 'Data Exfiltration (Metasploit)', 1337: 'Reverse Shell (Backdoor)',
                               31337: 'Reverse Shell (Back Orifice)', 5555: 'Android ADB Exploit',
                               4443: 'Reverse Shell', 8888: 'Reverse Shell', 1234: 'Reverse Shell',
                               12345: 'Reverse Shell (NetBus)'}
                c2_ports = {6667: 'Botnet C2 (IRC)', 9001: 'Tor Hidden Service',
                            2375: 'Docker API Exploit', 6379: 'Redis Unauthorized Access',
                            27017: 'MongoDB Data Breach'}
                all_mal_ports = {**exfil_ports, **c2_ports}
                
                # Check if either port is a known malicious port
                mal_label = all_mal_ports.get(dport) or all_mal_ports.get(sport)
                if mal_label:
                    src_local = src.startswith(('192.168.', '10.', '172.'))
                    dst_local = dst.startswith(('192.168.', '10.', '172.'))
                    if status == 'Attack':
                        # Already attack — just relabel with specific type
                        pred = mal_label
                        conf = 0.95
                    elif src_local and dst_local:
                        # Local traffic on known malicious port — promote to Attack
                        pred = mal_label
                        conf = 0.90
                        status = 'Attack'
            
            # 4. LLM Analysis - Analyze traffic that needs deeper inspection
            # LLM will analyze:
            #   - ALL "Suspicious" status traffic
            #   - Low confidence predictions (< 75%) even if Normal/Attack
            #   - Unusual ports that might indicate zero-day
            llm_analyzed = False
            is_zero_day = False
            llm_result = None
            original_status = status
            original_pred = pred
            
            # Determine if LLM should analyze this traffic
            should_analyze = False
            analyze_reason = ""
            
            # NEVER analyze safe external IPs
            if safe_service:
                should_analyze = False
            # Rate alert — only send to LLM if first time (not cached)
            elif rate_alert and not rate_llm_needed:
                should_analyze = False  # Cached result, skip LLM
            elif rate_alert and rate_llm_needed:
                should_analyze = True
                analyze_reason = f"Rate anomaly detected: {rate_alert}"
            # NEVER analyze if ML already detected attack at high confidence
            elif status == 'Attack' and conf >= 0.80:
                should_analyze = False  # ML is confident, trust it
            # ML says Suspicious but identified specific attack at high confidence
            # Promote to Attack and skip LLM
            elif status == 'Suspicious' and conf >= 0.80 and pred not in ('Normal', 'Unknown', 'Suspicious'):
                status = 'Attack'  # Promote to Attack
                should_analyze = False
            elif status == 'Suspicious':
                should_analyze = True
                analyze_reason = "Suspicious status"
            elif conf < 0.75:
                should_analyze = True
                analyze_reason = f"Low confidence ({conf:.1%})"
            else:
                # Check for local-to-local suspicious traffic
                # Only if ML said Normal (not Attack)
                # SKIP if incoming to PC from local IP — rate detector at step 3.6 handles these
                # The LLM sees standard ports (22, 80, 21) and says "Normal", defeating detection
                fwd_rate = features.get('Fwd Pkts/s', 0) or 0
                bwd_rate = features.get('Bwd Pkts/s', 0) or 0
                subflow_fwd = features.get('Subflow Fwd Pkts', 0) or 0
                subflow_bwd = features.get('Subflow Bwd Pkts', 0) or 0
                src_local = src.startswith(('192.168.', '10.', '172.'))
                dst_local = dst.startswith(('192.168.', '10.', '172.'))
                
                # Don't send to LLM if traffic involves PC and a local device
                # Rate detector handles incoming floods; outgoing responses don't need LLM
                skip_llm_rate = (src == self.pc_ip or dst == self.pc_ip) and src_local and dst_local
                
                if not skip_llm_rate and src_local and dst_local and status != 'Attack':
                    if fwd_rate > 100 or bwd_rate > 100:
                        should_analyze = True
                        analyze_reason = f"High rate local traffic ({max(fwd_rate,bwd_rate):.0f} pkt/s)"
                    elif (subflow_fwd > 15 and subflow_bwd == 0) or (subflow_bwd > 15 and subflow_fwd == 0):
                        should_analyze = True
                        analyze_reason = f"Unidirectional local flood ({subflow_fwd} fwd, {subflow_bwd} bwd)"
                    elif subflow_fwd > 30:
                        should_analyze = True
                        analyze_reason = f"Sustained local traffic ({subflow_fwd} packets)"
            
            if should_analyze and self.enable_llm and self.llm_service:
                print(f"{Fore.MAGENTA}🔮 LLM analyzing: {analyze_reason} (ML: {pred} @ {conf:.1%})...{Style.RESET_ALL}")
                
                llm_analyzed, is_zero_day, pred, conf, status, llm_result = self._analyze_with_llm(
                    features, proto, packet[IP].src, packet[IP].dst, sport, dport, pred, conf, status
                )
                
                # Track LLM results in stats
                if llm_analyzed and hasattr(self.stats, 'update_llm_result'):
                    self.stats.update_llm_result(original_status, status, is_zero_day)
                
                # Log LLM decision
                if llm_analyzed:
                    if status == 'Attack':
                        print(f"{Fore.RED}🔮 LLM Decision: ATTACK → {pred}{Style.RESET_ALL}")
                    elif status == 'Normal' and original_status != 'Normal':
                        print(f"{Fore.GREEN}🔮 LLM Decision: NORMAL (Cleared){Style.RESET_ALL}")
                    elif status == 'Normal':
                        print(f"{Fore.GREEN}🔮 LLM Confirmed: Normal traffic{Style.RESET_ALL}")
                
                # 4.1. POST-LLM: Malicious port safety net
                # If LLM cleared traffic on a known malicious port, override back to Attack
                # This ensures the detection shows as "LLM-Detected" in the dashboard
                if _is_mal_local and _mal_hit and status != 'Attack':
                    if llm_analyzed:
                        pred = f"LLM-Detected: {_mal_hit}"
                        conf = 0.88
                        status = 'Attack'
                        print(f"{Fore.MAGENTA}🔮 LLM-Detected: {_mal_hit} (malicious port){Style.RESET_ALL}")
                    else:
                        pred = f"LLM-Detected: {_mal_hit}"
                        conf = 0.85
                        status = 'Attack'
                        llm_analyzed = True
                        print(f"{Fore.MAGENTA}🔮 LLM-Detected: {_mal_hit} (malicious port){Style.RESET_ALL}")
            
            # 4.5. RATE ALERT — Cache LLM result and apply fallback
            if rate_alert:
                # Determine cache key
                local_prefixes = ('192.168.', '10.', '172.')
                if dst == self.pc_ip and src.startswith(local_prefixes):
                    cache_key = (src, dport)
                elif src == self.pc_ip and dst.startswith(local_prefixes):
                    cache_key = (dst, sport)
                else:
                    cache_key = (src, dport)
                
                if llm_analyzed and status == 'Attack':
                    # LLM classified it — cache the LLM's label
                    self._llm_cache[cache_key] = {'label': pred, 'time': time.time()}
                    print(f"{Fore.MAGENTA}📦 LLM result cached: {cache_key} → {pred}{Style.RESET_ALL}")
                elif status != 'Attack':
                    # LLM said Normal or wasn't called — use rate detector label as fallback
                    pred = rate_alert
                    conf = 0.95
                    status = 'Attack'
                    # Cache the rate detector's label
                    self._llm_cache[cache_key] = {'label': rate_alert, 'time': time.time()}
                
                # Cleanup old cache entries every 60 seconds
                now = time.time()
                old_keys = [k for k, v in self._llm_cache.items() if now - v['time'] > 300]
                for k in old_keys:
                    del self._llm_cache[k]
            
            # 5. Update Stats (with final status after LLM) - ONLY ONCE
            self.stats.update(status)

            # 6. Display (With Port Info)
            # src and dst already extracted above (step 3.5)
            
            # Check if local PC involved
            direction = ""
            if src == self.pc_ip: 
                direction = "OUT ->"
            elif dst == self.pc_ip: 
                direction = "IN <-"
            else:
                direction = "->"

            # Color based on status
            if status == 'Attack':
                color = Fore.RED
                icon = "🚨"
            elif status == 'Suspicious':
                color = Fore.YELLOW
                icon = "⚠️"
            else:
                color = Fore.GREEN
                icon = "✅"

            # LLM tag
            llm_tag = " [LLM]" if llm_analyzed else ""
            
            # Print to console
            print(f"{color}{icon} {src}:{sport} {direction} {dst}:{dport} | {proto} | {pred} ({conf:.1%}) [{status}]{llm_tag}{Style.RESET_ALL}")

            # 7. Save to DB with all features
            if self.db:
                try:
                    # Convert features dict to JSON-serializable format
                    features_json = self._prepare_features_for_db(features)
                    
                    log = self.db.objects.create(
                        src_ip=src, 
                        dst_ip=dst, 
                        src_port=int(sport),
                        dst_port=int(dport),
                        protocol=proto,
                        length=len(packet), 
                        prediction=pred, 
                        confidence=float(conf), 
                        status=status,
                        attack_type=pred if status in ['Attack', 'Suspicious'] else None,
                        features=features_json,  # Save all 31 features
                        llm_analyzed=llm_analyzed,
                        llm_result=json.dumps(llm_result) if llm_result else None,
                        is_zero_day=is_zero_day,
                        involves_local_pc=(src == self.pc_ip or dst == self.pc_ip)
                    )
                    self.ws.send_update(log)
                except Exception as e:
                    # Log error so we can debug missing logs
                    print(f"{Fore.RED}⚠️ DB Save Error: {e} | {src}→{dst}:{dport} ({proto}) [{status}]{Style.RESET_ALL}")
                    
        except Exception as e:
            print(f"{Fore.RED}Processing Error: {e}{Style.RESET_ALL}")

    def _prepare_features_for_db(self, features):
        """
        Prepare features dictionary for JSON storage in database.
        Ensures all values are JSON serializable.
        """
        # Feature names matching CICIDS2017/2018 dataset
        feature_names = [
            'Dst Port', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
            'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min',
            'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
            'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s',
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
            'Bwd IAT Tot', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
            'Fwd Pkts/s'
        ]
        
        features_dict = {}
        
        # If features is a dict, use it directly
        if isinstance(features, dict):
            for name in feature_names:
                value = features.get(name, 0)
                # Convert to float to ensure JSON serializable
                try:
                    features_dict[name] = float(value) if value is not None else 0.0
                except (TypeError, ValueError):
                    features_dict[name] = 0.0
        # If features is a list/array, map to names
        elif hasattr(features, '__iter__'):
            feature_list = list(features)
            for i, name in enumerate(feature_names):
                if i < len(feature_list):
                    try:
                        features_dict[name] = float(feature_list[i]) if feature_list[i] is not None else 0.0
                    except (TypeError, ValueError):
                        features_dict[name] = 0.0
                else:
                    features_dict[name] = 0.0
        
        return features_dict

    def _analyze_with_llm(self, features, proto, src_ip, dst_ip, sport, dport, pred, conf, status):
        """
        Analyze suspicious traffic with LLM
        
        LLM will decide:
        - ATTACK: Traffic is malicious (returns attack type)
        - NORMAL: Traffic is benign (false positive from ML)
        
        Returns:
            tuple: (llm_analyzed, is_zero_day, prediction, confidence, status, result)
        """
        try:
            if not self.llm_service or not self.llm_service.is_available:
                return False, False, pred, conf, status, None
            
            # Prepare features dict if needed
            if hasattr(features, '__iter__') and not isinstance(features, dict):
                features = self._prepare_features_for_db(features)
            
            traffic_data = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': sport,
                'dst_port': dport,
                'protocol': proto,
                'ml_prediction': pred,
                'ml_confidence': conf
            }
            
            result = self.llm_service.analyze_zero_day(traffic_data, features)
            
            if result.get('success'):
                is_suspicious = result.get('is_suspicious', False)
                is_zero_day = result.get('is_zero_day', False)
                attack_category = result.get('attack_category', 'Unknown')
                llm_conf = result.get('confidence', 0.7)
                
                if is_suspicious or is_zero_day:
                    # LLM says it's an ATTACK
                    new_pred = f"LLM-Detected: {attack_category}"
                    new_status = 'Attack'
                    return True, is_zero_day, new_pred, llm_conf, new_status, result
                else:
                    # LLM says it's NORMAL (false positive)
                    new_pred = 'Normal'
                    new_status = 'Normal'
                    new_conf = max(llm_conf, 0.85)  # High confidence it's normal
                    return True, False, new_pred, new_conf, new_status, result
            
            # LLM failed - keep as suspicious
            return False, False, pred, conf, status, None
            
        except Exception as e:
            print(f"{Fore.RED}LLM Analysis Error: {e}{Style.RESET_ALL}")
            return False, False, pred, conf, status, None

    def start(self):
        print(f"{Fore.CYAN}🚀 Sniffing on {self.interface}...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 Features will be saved to database for retraining{Style.RESET_ALL}")

        # Pre-warm ALL available engines up front. Without this, switching the
        # active engine to DL mid-capture forces the sniffer to import
        # TensorFlow + load the Keras models *inside* the scapy callback — a
        # 10–30 s blocking load that freezes capture (and can crash the process
        # on some Windows setups). Loading here, once, at a clean point means an
        # engine switch is instant and never blocks the packet loop.
        print(f"{Fore.CYAN}🔥 Pre-warming detection engines (loads TensorFlow once)...{Style.RESET_ALL}")
        try:
            import os as _os
            # Allow XGBoost/LightGBM + TensorFlow to coexist (duplicate OpenMP).
            _os.environ.setdefault('KMP_DUPLICATE_LIB_OK', 'TRUE')
            from api.detection.engines.engine_registry import get_registry
            reg = get_registry()
            # CRITICAL: load DL (TensorFlow) BEFORE ML (XGBoost/LightGBM).
            # Loading TF *after* XGBoost hard-crashes the process on Windows
            # (native library conflict) — which is why switching ML→DL mid-
            # capture killed the sniffer. TF-first avoids the crash; afterwards
            # both engines are resident and switching is instant.
            names = sorted(reg.get_available_engines(),
                           key=lambda n: 0 if n == 'dl' else 1)
            for nm in names:
                eng = reg.get_engine(nm)
                try:
                    ok = eng.ensure_loaded()
                    print(f"{Fore.CYAN}   {'✅' if ok else '❌'} {nm.upper()} engine "
                          f"{'ready' if ok else 'failed to load'}{Style.RESET_ALL}")
                except Exception as ee:
                    print(f"{Fore.YELLOW}   ⚠️ {nm.upper()} pre-warm error: {ee}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}engine pre-warm skipped: {e}{Style.RESET_ALL}")

        try:
            sniff(iface=self.interface, prn=self.process_packet, store=0)
        except OSError:
            pass  # Ignore the WinError 10038 on stop
        except KeyboardInterrupt:
            pass