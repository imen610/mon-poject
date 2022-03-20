from unicodedata import name
from django.urls import path 
from . import views
from rest_framework_simplejwt.views import (
    TokenRefreshView
)


urlpatterns=[
    path('register/',views.RegisterView.as_view(),name="register"),
    path('email-verify',views.verifyEmail.as_view(),name="email-verify"),
    path('login/',views.LoginAPIView.as_view(),name='login'),
    path('token/refresh/',TokenRefreshView.as_view(),name='token_refresh'),
    path('request-reset-email',views.RequestPasswordRestEmail.as_view(),name='request-reset-email'),
    path('password-reset/<uidb64>/<token>/',views.PasswordTokenCheckAPI.as_view(),name='password-reset-confirm'),
    path('password-reset-complete',views.SetNewPasswordAPIView.as_view(),name='password-reset-complete')
    
   
   ]