from django.urls import path
from .views import (
    EncryptFileView,
    DecryptFileView,
    SendMessageView,
    ReadMessageView,
    AuditLogView,
)

urlpatterns = [
    path("encrypt-file/", EncryptFileView.as_view(), name="encrypt-file"),
    path("decrypt-file/", DecryptFileView.as_view(), name="decrypt-file"),
    path("messages/", SendMessageView.as_view(), name="send-message"),
    path("messages/<int:message_id>/", ReadMessageView.as_view(), name="read-message"),
    path("journal/", AuditLogView.as_view(), name="audit-log"),
]