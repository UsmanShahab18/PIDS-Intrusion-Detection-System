"""
PIDS - ML Engine
Handles two-stage prediction with improved UDP traffic handling
Integrates with LLM for zero-day detection
"""
import os
import joblib
import pandas as pd
import numpy as np
from django.conf import settings
from colorama import Fore, Style

class MLEngine:
    def __init__(self, feature_list):
        self.model_stage1 = None
        self.model_stage2 = None
        self.label_encoder = None
        self.features_list = feature_list
        self.llm_service = None  # Will be initialized when needed
        
        # =================================================================
        # TUNING PARAMETERS - Adjust these to reduce false positives
        # =================================================================
        self.STAGE1_THRESHOLD = 0.7      # Increase = less false attacks (default was ~0.5)
        self.STAGE2_MIN_CONFIDENCE = 0.85  # Minimum confidence to declare attack
        self.UDP_THRESHOLD_BOOST = 0.1   # Extra threshold for UDP traffic
        self.LLM_CONFIDENCE_THRESHOLD = 0.6  # Trigger LLM when below this
        
        # Common normal UDP ports (DNS, NTP, DHCP, QUIC, etc.)
        self.NORMAL_UDP_PORTS = {
            53,    # DNS
            67, 68, # DHCP
            123,   # NTP
            137, 138, 139,  # NetBIOS
            443,   # QUIC/HTTP3
            500,   # IKE/IPSec
            1900,  # SSDP/UPnP
            3478, 3479,  # STUN/TURN (WebRTC)
            5353,  # mDNS
            5355,  # LLMNR
            8080, 8443,  # Common web
        }
        
        # Attack types that are commonly false positives for normal traffic
        self.SUSPICIOUS_ATTACK_TYPES = {
            'Infiltration',
            'Bot',
            'Portscan',
        }

    def load_models(self):
        """Load ML models from ml_models directory"""
        models_dir = os.path.join(settings.BASE_DIR, 'ml_models')
        try:
            self.model_stage1 = joblib.load(os.path.join(models_dir, 'stage1_xgboost.pkl'))
            self.model_stage2 = joblib.load(os.path.join(models_dir, 'stage2_lightgbm.pkl'))
            self.label_encoder = joblib.load(os.path.join(models_dir, 'label_encoder.pkl'))
            print(f"{Fore.GREEN}✅ ML Models loaded successfully{Style.RESET_ALL}")
            print(f"{Fore.CYAN}   Stage1 Threshold: {self.STAGE1_THRESHOLD}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}   Stage2 Min Confidence: {self.STAGE2_MIN_CONFIDENCE}{Style.RESET_ALL}")
            return True
        except Exception as e:
            print(f"{Fore.RED}❌ Error loading models: {e}{Style.RESET_ALL}")
            return False

    def predict(self, features, protocol='TCP'):
        """
        Make prediction using loaded models with improved accuracy
        
        Args:
            features: Dictionary of extracted features
            protocol: 'TCP' or 'UDP' - used for threshold adjustment
        
        Returns:
            Tuple: (prediction_label, confidence, status)
        """
        if not self.model_stage1:
            return 'Normal', 0.5, 'Normal'

        try:
            # Create DataFrame with correct feature order
            input_df = pd.DataFrame([features])[self.features_list]
            input_df = input_df.replace([np.inf, -np.inf], 0).fillna(0)

            # Get destination port for analysis
            dst_port = int(features.get('Dst Port', 0))
            
            # =============================================================
            # STAGE 1: Binary Classification (Normal vs Anomaly)
            # =============================================================
            stage1_proba = self.model_stage1.predict_proba(input_df)[0]
            anomaly_probability = stage1_proba[1] if len(stage1_proba) > 1 else stage1_proba[0]
            
            # Adjust threshold for UDP traffic on common ports
            threshold = self.STAGE1_THRESHOLD
            if protocol == 'UDP':
                threshold += self.UDP_THRESHOLD_BOOST
                # Extra boost for known normal UDP ports
                if dst_port in self.NORMAL_UDP_PORTS:
                    threshold += 0.15
            
            # Check if it passes the threshold
            is_anomaly = anomaly_probability > threshold
            
            if not is_anomaly:
                # It's normal traffic
                return 'Normal', 1 - anomaly_probability, 'Normal'
            
            # =============================================================
            # STAGE 2: Multi-class Attack Classification
            # =============================================================
            stage2_pred = self.model_stage2.predict(input_df)[0]
            stage2_proba = self.model_stage2.predict_proba(input_df)[0]
            
            attack_type = self.label_encoder.inverse_transform([stage2_pred])[0]
            confidence = float(max(stage2_proba))
            
            # =============================================================
            # POST-PROCESSING: Reduce False Positives
            # =============================================================
            
            # Check if confidence is high enough
            min_confidence = self.STAGE2_MIN_CONFIDENCE
            if protocol == 'UDP':
                min_confidence += 0.05  # Higher bar for UDP
            
            if confidence < min_confidence:
                # Low confidence - treat as suspicious, not attack
                return attack_type, confidence, 'Suspicious'
            
            # Extra check for commonly misclassified attack types
            if attack_type in self.SUSPICIOUS_ATTACK_TYPES:
                # For Infiltration specifically on UDP port 443 (QUIC), force Normal
                if attack_type == 'Infiltration' or attack_type == 'Infilteration':
                    # UDP on port 443 is almost always QUIC/HTTP3 - not an attack
                    if protocol == 'UDP' and dst_port == 443:
                        return 'Normal', 1 - anomaly_probability, 'Normal'
                    # Even with 100% confidence, if on normal port, it's likely false positive
                    if protocol == 'UDP' and dst_port in self.NORMAL_UDP_PORTS:
                        return 'Normal', 1 - anomaly_probability, 'Normal'
                    # For other cases, require extremely high confidence
                    if confidence < 0.99:
                        return 'Normal', 1 - anomaly_probability, 'Normal'
                # For other suspicious types, require higher confidence
                elif confidence < 0.92:
                    return attack_type, confidence, 'Suspicious'
                
                # Check if it's on a normal port
                if protocol == 'UDP' and dst_port in self.NORMAL_UDP_PORTS:
                    return 'Normal', 1 - confidence, 'Normal'
            
            # =============================================================
            # FINAL DECISION
            # =============================================================
            return attack_type, confidence, 'Attack'
            
        except Exception as e:
            print(f"{Fore.RED}ML Error: {e}{Style.RESET_ALL}")
            return 'Unknown', 0.0, 'Unknown'
    
    def get_attack_severity(self, attack_type, confidence):
        """
        Determine severity level based on attack type and confidence
        
        Returns: 'Critical', 'High', 'Medium', or 'Low'
        """
        CRITICAL_ATTACKS = {'DDoS', 'DoS Hulk', 'DoS GoldenEye', 'DoS Slowloris', 'DoS slowhttptest'}
        HIGH_ATTACKS = {'Bot', 'Infiltration', 'Web Attack', 'SQL Injection', 'XSS'}
        MEDIUM_ATTACKS = {'PortScan', 'FTP-Patator', 'SSH-Patator', 'Brute Force'}
        
        if attack_type in CRITICAL_ATTACKS and confidence > 0.9:
            return 'Critical'
        elif attack_type in HIGH_ATTACKS and confidence > 0.85:
            return 'High'
        elif attack_type in MEDIUM_ATTACKS and confidence > 0.8:
            return 'Medium'
        else:
            return 'Low'
    
    def _get_llm_service(self):
        """Lazy load LLM service"""
        if self.llm_service is None:
            try:
                from .llm_service import get_llm_service
                self.llm_service = get_llm_service()
            except ImportError:
                print(f"{Fore.YELLOW}⚠️ LLM Service not available{Style.RESET_ALL}")
                self.llm_service = None
        return self.llm_service
    
    def predict_with_llm(self, features, protocol='TCP', traffic_data=None):
        """
        Make prediction with optional LLM analysis for uncertain cases
        
        Args:
            features: Dictionary of extracted features
            protocol: 'TCP' or 'UDP'
            traffic_data: Optional dict with src_ip, dst_ip, ports for LLM context
        
        Returns:
            Tuple: (prediction, confidence, status, llm_analysis)
        """
        # First, get ML prediction
        prediction, confidence, status = self.predict(features, protocol)
        llm_analysis = None
        
        # Check if we should use LLM for additional analysis
        if status == 'Suspicious' or (status == 'Attack' and confidence < self.LLM_CONFIDENCE_THRESHOLD):
            llm = self._get_llm_service()
            if llm and llm.is_available and traffic_data:
                # Prepare data for LLM
                llm_data = {
                    **traffic_data,
                    'protocol': protocol,
                    'ml_prediction': prediction,
                    'ml_confidence': confidence
                }
                
                # Get LLM analysis
                result = llm.analyze_zero_day(llm_data, features)
                
                if result.get('success'):
                    llm_analysis = result
                    
                    # If LLM says it's a zero-day with high confidence
                    if result.get('is_zero_day') and result.get('confidence', 0) > 0.7:
                        status = 'Attack'
                        prediction = f"LLM-Detected: {result.get('attack_category', 'Unknown')}"
                        print(f"{Fore.MAGENTA}🔮 LLM Detection: {prediction}{Style.RESET_ALL}")
                    
                    # If LLM says it's benign with high confidence
                    elif not result.get('is_suspicious') and result.get('confidence', 0) > 0.8:
                        status = 'Normal'
                        prediction = 'Normal'
                        print(f"{Fore.CYAN}🔮 LLM Override: Benign traffic{Style.RESET_ALL}")
        
        return prediction, confidence, status, llm_analysis