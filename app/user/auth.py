from rest_framework.authentication import BaseAuthentication
from django.contrib.auth.hashers import check_password

from core.models import User, PersonalAccessToken


class PersonalAccessTokenAuthentication(BaseAuthentication):

    def authenticate(self, request, username, token):
        try:
            user = User.objects.get(username=username)
            tokens = PersonalAccessToken.objects.filter(user=user, revoked=False, is_expired=False)
            for stored in tokens:
                if check_password(token, stored.token):
                    if PersonalAccessToken.objects.checkExpiration(stored):
                        return user
            return None
        except Exception as error:
            return None

