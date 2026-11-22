from django.db import models
from django.conf import settings
from django.core.exceptions import ValidationError


class KeyMetadata(models.Model):
    class State(models.TextChoices):
        ACTIVE = "active", "Active"
        ROTATING = "rotating", "En rotation"
        REVOKED = "revoked", "Révoquée"
        DESTROYED = "destroyed", "Détruite"

    version = models.PositiveIntegerField(unique=True)
    state = models.CharField(max_length=20, choices=State.choices, default=State.ACTIVE)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)


class Message(models.Model):
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="sent_messages")
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="received_messages")
    ciphertext = models.BinaryField()
    nonce = models.CharField(max_length=24)
    encrypted_dek = models.BinaryField()
    key_version = models.PositiveIntegerField()
    sha256 = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    read_at = models.DateTimeField(null=True, blank=True)


class SensitiveFile(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="sensitive_files")
    name = models.CharField(max_length=255)
    encrypted_path = models.CharField(max_length=500)
    size = models.PositiveBigIntegerField(default=0)
    sha256 = models.CharField(max_length=64)
    nonce = models.CharField(max_length=24)
    encrypted_dek = models.BinaryField()
    key_version = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)


class VaultCredential(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="vault_credentials")
    service = models.CharField(max_length=255)
    login = models.CharField(max_length=255)
    ciphertext = models.BinaryField()
    nonce = models.CharField(max_length=24)
    encrypted_dek = models.BinaryField()
    key_version = models.PositiveIntegerField()


class AuditLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True)
    action = models.CharField(max_length=100)
    target = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)
    result = models.CharField(max_length=30)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    previous_hash = models.CharField(max_length=64, blank=True)
    hash = models.CharField(max_length=64, unique=True)

    class Meta:
        ordering = ["timestamp", "id"]

    def delete(self, *args, **kwargs):
        raise ValidationError("Les lignes du journal sont non modifiables.")

    def save(self, *args, **kwargs):
        if self.pk:
            raise ValidationError("Les lignes du journal sont non modifiables.")
        super().save(*args, **kwargs)

# Create your models here.
