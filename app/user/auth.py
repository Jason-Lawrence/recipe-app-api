from rest_framework.authentication import TokenAuthentication
from rest_framework import HTTP_HEADER_ENCODING, exceptions
from django.contrib.auth.hashers import check_password
from django.utils.translation import gettext_lazy as _

from core.models import User, PersonalAccessToken


def get_authorization_header(request):
    auth = request.META.get('HTTP_AUTHORIZATION', b'')
    if isinstance(auth, str):
        auth = auth.encode(HTTP_HEADER_ENCODING)
    return auth


class PersonalAccessTokenAuthentication(TokenAuthentication):

    keyword = 'PAT'
    model = PersonalAccessToken

    def authenticate(self, request):

        auth = get_authorization_header(request).split()

        if not auth or auth[0].lower() != self.keyword.lower().encode():
           return None

        if len(auth) == 1:
            msg = _('Invalid token header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid token header. Token string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            token = auth[1].decode()

        except UnicodeError:
            msg = _('Invalid token header. Token string should not contain invalid characters.')
            raise exceptions.AuthenticationFailed(msg)

        return self.authenticate_credentials(token)

    def authenticate_credentials(self, token):
        try:
            auth_token = None
            stored_tokens = PersonalAccessToken.objects.filter(revoked=False, is_expired=False)
            for stored in stored_tokens:
                if check_password(token, stored.token):
                    auth_token = stored
                    break
        except:
            raise exceptions.AuthenticationFailed(_('Authentication Failed'))

        if not auth_token:
            raise exceptions.AuthenticationFailed(_('Invalid token.'))

        if PersonalAccessToken.objects.checkExpiration(auth_token):
            return (auth_token.user, auth_token)
