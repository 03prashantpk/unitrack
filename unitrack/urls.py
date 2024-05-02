"""
URL configuration for unitrack project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
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
from main import views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("send_otp/", views.send_otp, name="send_otp"),
    path('verify_otp/', views.verify_otp, name='verify_otp'),
    path("register/", views.register, name="register"),
    path("login/", views.login, name="login"),
    path("logout/", views.logout, name="logout"),
    path("home/", views.home, name="home"),
    path("profile/", views.profile, name="profile"),
    path("reset_password/", views.reset_password, name='reset_password'),
    path('update_user_profile/', views.update_user_profile, name='update_user_profile'),
    path('add_review/', views.add_review, name='add_review'),
    path('all_reviews/', views.all_reviews, name='all_reviews'),
    path('create_issues/', views.add_global_issues, name='create_issues'),
    path('rms/', views.rms, name='rms'),
    path('log_rms/', views.log_rms, name='log_rms'),
    path('rms_status/', views.rms_status, name='rms_status'),
    path('rms_status/<str:rms_id>/', views.rms_details, name='rms_details'),
    path('rms_chat/<str:rms_id>/', views.rms_chat, name='rms_chat'),
    path('rms_chats/<str:rms_id>/', views.rms_chats, name='rms_chats'),
    path('', views.index, name='index')
    # if any other user redirect to 404
    
]
