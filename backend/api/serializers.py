from rest_framework import serializers
from .models import TrafficLog, SystemAlert, Alert


class TrafficLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = TrafficLog
        fields = [
            'id', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'protocol', 'length', 'prediction', 'confidence', 'status',
            'attack_type', 'llm_analyzed', 'llm_result', 'is_zero_day',
            'involves_local_pc', 'features', 'acknowledged', 'acknowledged_at'
        ]
    
    def to_representation(self, instance):
        """Custom representation for frontend"""
        data = super().to_representation(instance)
        if instance.timestamp:
            data['timestamp'] = instance.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        if instance.acknowledged_at:
            data['acknowledged_at'] = instance.acknowledged_at.strftime('%Y-%m-%d %H:%M:%S')
        return data


class SystemAlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = SystemAlert
        fields = '__all__'


class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        fields = '__all__'


class StatsSerializer(serializers.Serializer):
    total_traffic = serializers.IntegerField()
    attacks = serializers.IntegerField()
    suspicious = serializers.IntegerField()
    normal = serializers.IntegerField()
    attack_percentage = serializers.FloatField()
    llm_analyzed = serializers.IntegerField(default=0)
    llm_attacks = serializers.IntegerField(default=0)
    llm_normal = serializers.IntegerField(default=0)
    zero_day = serializers.IntegerField(default=0)