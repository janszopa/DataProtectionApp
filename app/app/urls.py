"""
URL configuration for app project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from .views.user_views import login_view, register_view, logout_view, setup_2fa_view, verify_2fa_view, profile_view, change_password_view, verify_change_password_view, reset_password_view, verify_reset_password_view
from .views.message_views import messages_view, create_message_view, verify_message_view

urlpatterns = [
    path('', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('setup-2fa/', setup_2fa_view, name='setup_2fa'),
    path('verify-2fa/', verify_2fa_view, name='verify_2fa'),
    path('logout/', logout_view, name='logout'),
    path('messages/', messages_view, name='messages'),
    path('create-message/', create_message_view, name='create_message'),
    path('profile/', profile_view, name='profile'),
    path('change-password/', change_password_view, name='change_password'),
    path('verify-change-password/', verify_change_password_view, name='verify_change_password'),
    path('verify-message/<int:message_id>/', verify_message_view, name='verify_message'),    
    path('reset-password/', reset_password_view, name='reset_password'),
    path('verify-reset-password/', verify_reset_password_view, name='verify_reset_password'),
]
