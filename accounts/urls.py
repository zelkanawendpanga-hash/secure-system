from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token
from .views import RegisterView, MeView, LoginView, EnableMfaView, ConfirmMfaView, LogoutView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("me/", MeView.as_view(), name="me"),
    path("login/", LoginView.as_view(), name="login"),
    path("token/", obtain_auth_token, name="token"),
    path("mfa/enable/", EnableMfaView.as_view(), name="mfa-enable"),
    path("mfa/confirm/", ConfirmMfaView.as_view(), name="mfa-confirm"),
    path("logout/", LogoutView.as_view(), name="logout"),
]