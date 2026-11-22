from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

class User(AbstractUser):
    email = models.EmailField(unique=True)
    ROLE_EMPLOYEE = "employee"
    ROLE_ADMIN = "admin"
    ROLE_AUDITOR = "auditor"
    ROLE_CHOICES = [
        (ROLE_EMPLOYEE, "Employé"),
        (ROLE_ADMIN, "Administrateur"),
        (ROLE_AUDITOR, "Auditeur"),
    ]

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_EMPLOYEE)
    mfa_secret = models.CharField(max_length=64, blank=True, default="")
    mfa_enabled = models.BooleanField(default=False)
    failed_attempts = models.PositiveSmallIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)

    @property
    def is_locked(self):
        return bool(self.locked_until and self.locked_until > timezone.now())

    def __str__(self):
        return self.username