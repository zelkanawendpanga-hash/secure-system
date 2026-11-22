from rest_framework import serializers

from .models import AuditLog


class FileEncryptSerializer(serializers.Serializer):
    file = serializers.FileField()
    key = serializers.CharField(required=False, allow_blank=True)


class FileDecryptSerializer(serializers.Serializer):
    file = serializers.FileField()
    key = serializers.CharField(required=False, allow_blank=True)


class AuditLogSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True, default="")

    class Meta:
        model = AuditLog
        fields = ["id", "username", "action", "target", "timestamp", "result", "ip_address", "previous_hash", "hash"]
