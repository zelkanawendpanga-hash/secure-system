from django.test import TestCase
from rest_framework.test import APIClient

from accounts.models import User


class SecurityApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="alice",
            email="alice@example.com",
            password="StrongPassword123!",
        )
        self.client = APIClient()
        token = self._token()
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {token}")

    def _token(self):
        from rest_framework.authtoken.models import Token
        token, _ = Token.objects.get_or_create(user=self.user)
        return token.key

    def test_send_and_read_message(self):
        response = self.client.post("/api/security/messages/", {
            "recipient": self.user.id,
            "content": "Information confidentielle",
        }, format="json")
        self.assertEqual(response.status_code, 201)

        message_id = response.data["id"]
        read = self.client.get(f"/api/security/messages/{message_id}/")
        self.assertEqual(read.status_code, 200)
        self.assertEqual(read.data["content"], "Information confidentielle")
