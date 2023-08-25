from django.urls import path
from rest_framework_simplejwt.views import(
    TokenRefreshView,
    TokenVerifyView
)

from user import views


app_name = 'user'

urlpatterns = [
    path('create/', views.CreateUserView.as_view(), name='create'),
    path('token/', views.AuthTokenView.as_view(), name='token'),
    path('me/', views.ManageUserView.as_view(), name='me'),
    path('auth-token/',views.AuthUserView.as_view(), name='auth-token'),
    path('auth-token/verify', TokenVerifyView.as_view(), name='token_verify'),
    path('auth-token/refresh', TokenRefreshView.as_view(), name='token_refresh')
]
