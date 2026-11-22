import hashlib
import os

from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.http import HttpResponse
from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import FileEncryptSerializer, FileDecryptSerializer
from .serializers import AuditLogSerializer
from .models import AuditLog, KeyMetadata, Message, SensitiveFile
from .utils import encrypt_bytes, decrypt_bytes


def add_audit(request, action, target, result):
    latest = AuditLog.objects.order_by("-timestamp", "-id").first()
    previous = latest.hash if latest else "0" * 64
    timestamp = timezone.now()
    payload = f"{previous}|{request.user.pk if request.user.is_authenticated else ''}|{action}|{target}|{timestamp.isoformat()}|{result}|{request.META.get('REMOTE_ADDR', '')}"
    AuditLog.objects.create(
        user=request.user if request.user.is_authenticated else None,
        action=action,
        target=target,
        timestamp=timestamp,
        result=result,
        ip_address=request.META.get("REMOTE_ADDR"),
        previous_hash=previous,
        hash=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
    )

class EncryptFileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = FileEncryptSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uploaded_file = serializer.validated_data["file"]
        data = uploaded_file.read()
        ciphertext, nonce, encrypted_dek, sha256 = encrypt_bytes(data)
        key_metadata, _ = KeyMetadata.objects.get_or_create(version=1)
        rel_path = default_storage.save(
            f"sensitive/{uploaded_file.name}.enc",
            ContentFile(ciphertext),
        )
        record = SensitiveFile.objects.create(
            owner=request.user,
            name=uploaded_file.name,
            encrypted_path=rel_path,
            size=len(data),
            sha256=sha256,
            nonce=nonce.hex(),
            encrypted_dek=encrypted_dek,
            key_version=key_metadata.version,
        )
        add_audit(request, "file_encrypt", uploaded_file.name, "success")
        return Response({"id": record.id, "name": record.name, "sha256": record.sha256})

class DecryptFileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = FileDecryptSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uploaded_file = serializer.validated_data["file"]
        original_name = uploaded_file.name
        if original_name.endswith(".enc"):
            original_name = original_name[:-4]
        record = SensitiveFile.objects.filter(owner=request.user, name=original_name).first()
        if not record:
            record = SensitiveFile.objects.filter(owner=request.user, name=uploaded_file.name).first()
        if not record:
            add_audit(request, "file_decrypt", uploaded_file.name, "failure")
            return Response({"detail": "Fichier sécurisé introuvable."}, status=status.HTTP_404_NOT_FOUND)
        try:
            ciphertext = default_storage.open(record.encrypted_path, "rb").read()
            decrypted = decrypt_bytes(
                ciphertext,
                bytes.fromhex(record.nonce),
                bytes(record.encrypted_dek),
            )
            if hashlib.sha256(decrypted).hexdigest() != record.sha256:
                raise ValueError("Empreinte invalide")
        except Exception:
            add_audit(request, "file_decrypt", uploaded_file.name, "failure")
            return Response({"detail": "Impossible de déchiffrer le fichier."}, status=status.HTTP_400_BAD_REQUEST)

        response = HttpResponse(decrypted, content_type="application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{original_name}"'
        add_audit(request, "file_decrypt", original_name, "success")
        return response


class SendMessageView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        recipient_id = request.data.get("recipient")
        plain_text = str(request.data.get("content", ""))
        if not recipient_id or not plain_text:
            return Response({"detail": "Destinataire et contenu requis."}, status=status.HTTP_400_BAD_REQUEST)
        from django.contrib.auth import get_user_model
        recipient = get_user_model().objects.filter(pk=recipient_id).first()
        if not recipient:
            return Response({"detail": "Destinataire introuvable."}, status=status.HTTP_404_NOT_FOUND)

        ciphertext, nonce, encrypted_dek, sha256 = encrypt_bytes(plain_text.encode("utf-8"))
        message = Message.objects.create(
            sender=request.user,
            recipient=recipient,
            ciphertext=ciphertext,
            nonce=nonce.hex(),
            encrypted_dek=encrypted_dek,
            key_version=1,
            sha256=sha256,
        )
        add_audit(request, "message_send", str(recipient.username), "success")
        return Response({"id": message.id}, status=status.HTTP_201_CREATED)


class ReadMessageView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, message_id):
        message = Message.objects.filter(pk=message_id).first()
        if not message:
            return Response({"detail": "Message introuvable."}, status=status.HTTP_404_NOT_FOUND)
        if message.recipient_id != request.user.id:
            add_audit(request, "message_read", str(message_id), "denied")
            return Response({"detail": "Accès refusé."}, status=status.HTTP_403_FORBIDDEN)
        try:
            plaintext = decrypt_bytes(
                bytes(message.ciphertext),
                bytes.fromhex(message.nonce),
                bytes(message.encrypted_dek),
            )
            if hashlib.sha256(plaintext).hexdigest() != message.sha256:
                raise ValueError("Empreinte invalide")
        except Exception:
            add_audit(request, "message_read", str(message_id), "failure")
            return Response({"detail": "Le contenu chiffré est invalide."}, status=status.HTTP_400_BAD_REQUEST)
        if not message.read_at:
            message.read_at = timezone.now()
            message.save(update_fields=["read_at"])
        add_audit(request, "message_read", str(message_id), "success")
        return Response({"content": plaintext.decode("utf-8"), "sender": message.sender.username})


class AuditLogView(ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = AuditLogSerializer

    def get_queryset(self):
        if self.request.user.role not in ("admin", "auditor"):
            return AuditLog.objects.none()
        return AuditLog.objects.all()