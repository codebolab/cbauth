from django.urls import path
from django.contrib.auth.views import (
    LoginView,
    LogoutView
)
from django.contrib.auth.decorators import login_required
from django.views.generic import TemplateView


urlpatterns = [
    path('login', LoginView.as_view(template_name="auth.login.html"),
         name='auth_login'),
    path('logout', LogoutView.as_view(next_page='/'), name='auth_logout'),
    path('', login_required(TemplateView.as_view(template_name="auth.main.html")),
         name='auth_main'),
]
