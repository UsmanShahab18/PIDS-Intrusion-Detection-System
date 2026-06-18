# api/consumers.py - JWT Authenticated WebSocket
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from .models import TrafficLog
from urllib.parse import parse_qs


class PacketConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Verify JWT token from query string: ws://host/ws/traffic/?token=xxx
        query_string = self.scope.get('query_string', b'').decode()
        params = parse_qs(query_string)
        token = params.get('token', [None])[0]
        
        if not token:
            print("❌ WebSocket rejected: No token provided")
            await self.close()
            return
        
        # Verify the JWT token
        try:
            from .auth_utils import _verify_jwt
            payload = _verify_jwt(token)
            if payload.get('type') != 'access':
                print("❌ WebSocket rejected: Not an access token")
                await self.close()
                return
            self.user_id = payload.get('user_id')
            self.username = payload.get('username', 'unknown')
        except ValueError as e:
            print(f"❌ WebSocket rejected: {e}")
            await self.close()
            return

        # Join the group
        await self.channel_layer.group_add(
            'packet_updates',
            self.channel_name
        )
        await self.accept()
        print(f"✅ WebSocket connected: {self.username} (authenticated)")
        
        # Send recent traffic history
        try:
            recent_logs = await sync_to_async(list)(
                TrafficLog.objects.order_by('-timestamp')[:50]
            )
            
            for log in recent_logs:
                await self.send(text_data=json.dumps({
                    'type': 'packet',
                    'data': {
                        'id': log.id,
                        'timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                        'src_ip': log.src_ip,
                        'dst_ip': log.dst_ip,
                        'src_port': log.src_port,
                        'dst_port': log.dst_port,
                        'protocol': log.protocol,
                        'status': log.status,
                        'prediction': log.prediction,
                        'confidence': log.confidence,
                        'attack_type': log.attack_type or 'Normal',
                        'length': log.length,
                        'is_local': getattr(log, 'involves_local_pc', False),
                    }
                }))
            print(f"✅ Sent {len(recent_logs)} recent logs to {self.username}")
        except Exception as e:
            print(f"⚠ Error sending recent logs: {e}")

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            'packet_updates',
            self.channel_name
        )
        username = getattr(self, 'username', 'unknown')
        print(f"❌ WebSocket disconnected: {username}")

    async def send_packet(self, event):
        """Receive packet data from start_sniffer command"""
        data = event['data']
        await self.send(text_data=json.dumps({
            'type': 'packet',
            'data': data
        }))