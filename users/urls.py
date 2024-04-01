from django.urls import path
from .views import RegisterView, LoginView, UserInfoView, RefreshTokenView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('user/', UserInfoView.as_view(), name='user-info'),
    path('refresh-token/', RefreshTokenView.as_view(), name='refresh-token'),
]