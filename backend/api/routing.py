# api/routing.py
from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r'ws/packets/$', consumers.PacketConsumer.as_asgi()),
    re_path(r'ws/traffic/$', consumers.PacketConsumer.as_asgi()),
]