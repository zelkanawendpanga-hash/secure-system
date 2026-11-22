from rest_framework import serializers

class FileEncryptSerializer(serializers.Serializer):
    file = serializers.FileField()
    key = serializers.CharField(required=False, allow_blank=True)

class FileDecryptSerializer(serializers.Serializer):
    file = serializers.FileField()
    key = serializers.CharField(required=False, allow_blank=True)