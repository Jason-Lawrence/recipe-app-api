from django.contrib.auth import get_user_model, authenticate
from django.utils.translation import gettext_lazy as _
from django.conf import settings

from rest_framework import(
    generics,
    permissions,
    status,
    serializers
)
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication

from drf_spectacular.utils import(
    extend_schema,
    inline_serializer
)

from user.auth import PersonalAccessTokenAuthentication
from user.serializers import UserSerializer

from cryptography.fernet import Fernet


class CreateUserView(generics.CreateAPIView):
    authentication_classes =[]

    serializer_class = UserSerializer


class AuthTokenView(APIView):

    authentication_classes = [PersonalAccessTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        msg = _(f"User: {request.user.name} is authenticated!")
        return Response({'msg': msg}, status=status.HTTP_200_OK)


@extend_schema(
    request=inline_serializer(
        name='RequestJWT',
        fields={
            'username': serializers.CharField(),
            'encrypted_password': serializers.CharField()
        }
    )
)
class AuthUserView(APIView):

    def post(self, request):
        try:
            email = request.data.get('email')
            encrypted = request.data.get('encrypted_password')
            key = settings.FERNET_SECRET_KEY.encode()
            cipher_suite = Fernet(key)
            decrypted = cipher_suite.decrypt(encrypted.encode()).decode('utf-8')
            user = authenticate(request, username=email, password=decrypted)

            if user:
                refresh = RefreshToken.for_user(user)
                data = {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }
                return Response (data, status=status.HTTP_200_OK)

            else:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class ManageUserView(generics.RetrieveUpdateAPIView):

    serializer_class = UserSerializer
    authentication_classes = [PersonalAccessTokenAuthentication, JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user
