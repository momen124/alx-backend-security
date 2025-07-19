from django.urls import path
from . import views
from django.db import models
from django.utils import timezone

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('api/login/', views.api_login, name='api_login'),
    path('api/stats/', views.api_stats, name='api_stats'),
    path('api/block-ip/', views.block_ip_view, name='block_ip'),
    path('test-rate-limit/', views.test_rate_limit, name='test_rate_limit'),
]