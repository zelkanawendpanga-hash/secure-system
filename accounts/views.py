import base64
import hashlib
import hmac
import secrets
import struct
import time

from django.utils import timezone
from rest_framework import generics, permissions, status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User
from .serializers import UserSerializer

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

class MeView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user


def generate_mfa_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def verify_totp(secret, code, period=30, digits=6):
    if not secret or not code:
        return False
    try:
        decoded = base64.b32decode(secret + "=" * (-len(secret) % 8))
    except (base64.binascii.Error, ValueError):
        return False

    counter = int(time.time()) // period
    for offset in (-1, 0, 1):
        value = struct.pack(">Q", counter + offset)
        digest = hmac.new(decoded, value, hashlib.sha1).digest()
        index = digest[-1] & 0x0F
        binary = struct.unpack(">I", digest[index:index + 4])[0] & 0x7FFFFFFF
        expected = str(binary % (10 ** digits)).zfill(digits)
        if hmac.compare_digest(expected, str(code).strip()):
            return True
    return False


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get("username", "").strip()
        password = request.data.get("password", "")
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({"detail": "Identifiants invalides."}, status=status.HTTP_401_UNAUTHORIZED)

        if user.is_locked:
            return Response({"detail": "Compte temporairement verrouillé."}, status=status.HTTP_423_LOCKED)

        if not user.check_password(password):
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.locked_until = timezone.now() + timezone.timedelta(minutes=15)
            user.save(update_fields=["failed_attempts", "locked_until"])
            return Response({"detail": "Identifiants invalides."}, status=status.HTTP_401_UNAUTHORIZED)

        user.failed_attempts = 0
        user.locked_until = None
        user.save(update_fields=["failed_attempts", "locked_until"])

        code = request.data.get("mfa_code")
        if user.mfa_enabled:
            if not verify_totp(user.mfa_secret, code):
                return Response({"detail": "Code MFA requis ou invalide."}, status=status.HTTP_401_UNAUTHORIZED)

        token, _ = Token.objects.get_or_create(user=user)
        return Response({"token": token.key, "user": UserSerializer(user).data})


class EnableMfaView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        secret = generate_mfa_secret()
        request.user.mfa_secret = secret
        request.user.save(update_fields=["mfa_secret"])
        return Response({"secret": secret})


class ConfirmMfaView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        code = request.data.get("code")
        if not verify_totp(request.user.mfa_secret, code):
            return Response({"detail": "Code MFA invalide."}, status=status.HTTP_400_BAD_REQUEST)
        request.user.mfa_enabled = True
        request.user.save(update_fields=["mfa_enabled"])
        return Response({"detail": "MFA activée."})


class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        Token.objects.filter(user=request.user).delete()
        return Response({"detail": "Déconnexion effectuée."})