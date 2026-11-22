from django.test import TestCase
from rest_framework.test import APIClient

from .models import User


class AuthenticationTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_register_and_login(self):
        response = self.client.post("/api/accounts/register/", {
            "username": "alice",
            "email": "alice@example.com",
            "password": "StrongPassword123!",
        }, format="json")
        self.assertEqual(response.status_code, 201)

        login = self.client.post("/api/accounts/login/", {
            "username": "alice",
            "password": "StrongPassword123!",
        }, format="json")
        self.assertEqual(login.status_code, 200)
        self.assertIn("token", login.data)

    def test_registration_ignores_admin_role(self):
        response = self.client.post("/api/accounts/register/", {
            "username": "employee",
            "email": "employee@example.com",
            "password": "StrongPassword123!",
            "role": "admin",
        }, format="json")
        self.assertEqual(response.status_code, 201)
        user = User.objects.get(username="employee")
        self.assertEqual(user.role, User.ROLE_EMPLOYEE)
