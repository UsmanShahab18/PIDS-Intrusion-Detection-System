from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

class WebSocketManager:
    def __init__(self):
        self.channel_layer = get_channel_layer()

    def send_update(self, log_entry):
        """Send log entry to frontend"""
        try:
            data = {
                'id': log_entry.id,
                'timestamp': log_entry.timestamp.strftime('%H:%M:%S'),
                
                # === FIX: Standardize keys to match DB ===
                'src_ip': log_entry.src_ip,      
                'dst_ip': log_entry.dst_ip,      
                # ========================================

                # === NEW: Add Ports ===
                'src_port': log_entry.src_port,
                'dst_port': log_entry.dst_port,
                # ======================

                'protocol': log_entry.protocol,
                'status': log_entry.status,
                'prediction': log_entry.prediction,
                'confidence': log_entry.confidence,
                'length': log_entry.length,
                'is_local': log_entry.involves_local_pc
            }
            
            async_to_sync(self.channel_layer.group_send)(
                'packet_updates',
                {'type': 'send_packet', 'data': data}
            )
        except Exception:
            pass # Silent fail