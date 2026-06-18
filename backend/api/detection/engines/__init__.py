"""
Detection engines.

Each engine implements :class:`BaseEngine` and is loaded lazily on first
prediction. The registry (``engine_registry.py``) decides which engine is
active for a given request.
"""
