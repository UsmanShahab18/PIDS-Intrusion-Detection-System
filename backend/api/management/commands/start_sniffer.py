# backend/api/management/commands/start_sniffer.py

from django.core.management.base import BaseCommand
from django.apps import apps
import time
from colorama import init

# Import our new modules
from .pids_core.network_utils import NetworkUtils
from .pids_core.feature_extractor import FeatureExtractor
from .pids_core.stats_manager import StatsManager
from .pids_core.websocket_manager import WebSocketManager
from .pids_core.traffic_capture import TrafficCapture
from .pids_core.traffic_simulator import TrafficSimulator
# Phase 2a: detection now goes through the engine registry (ML / DL).
# The legacy MLEngine is no longer instantiated here.
from api.detection.engines.engine_registry import get_registry

init(autoreset=True)

class Command(BaseCommand):
    help = 'Start PIDS Sniffer'

    def handle(self, *args, **kwargs):
        # 1. Initialize Components
        net_utils = NetworkUtils()
        feature_ext = FeatureExtractor()
        stats = StatsManager()
        ws_manager = WebSocketManager()

        # 2. Detection engine — selected at runtime via the registry
        #    (ML or DL, persisted in EngineConfig DB row, 5-second
        #    cached for the per-packet hot path). Models are loaded
        #    lazily on the first prediction.
        active = get_registry().get_active_engine()
        print(f"🤖 Active detection engine: {active.name.upper()} (lazy-loaded on first packet)")
        try:
            TrafficLog = apps.get_model('api', 'TrafficLog')
        except Exception as e:
            print(f"⚠️ Could not load TrafficLog model: {e}")
            TrafficLog = None

        # 3. User Selection
        print("1. Real Mode")
        print("2. Test Mode")
        choice = input("Select: ").strip()

        if choice == '1':
            # Real Mode
            interface = net_utils.get_best_interface()
            if not interface:
                print("No interface found.")
                return

            capturer = TrafficCapture(
                interface, feature_ext, None,  # ml_engine arg is legacy / unused
                stats, ws_manager, TrafficLog, net_utils.your_ip
            )
            capturer.start()

        else:
            # Test Mode
            sim = TrafficSimulator(stats, ws_manager, TrafficLog, net_utils.your_ip)
            try:
                while True:
                    sim.generate_packet()
                    time.sleep(1) # Delay between fake packets
            except KeyboardInterrupt:
                pass

        # 4. Finish
        stats.show_final_stats()