from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.conf import settings

from rest_framework.test import APIClient
from rest_framework import status

from core.models import PersonalAccessToken
from datetime import date
from cryptography.fernet import Fernet


CREATE_USER_URL = reverse('user:create')
TOKEN_URL = reverse('user:token')
ME_URL = reverse('user:me')
AUTHTOKEN_URL = reverse('user:auth-token')


def create_user(**params):
    return get_user_model().objects.create_user(**params)


class PublicUserApiTests(TestCase):

    def setUp(self):
        self.client = APIClient()

    def test_create_user_success(self):
        payload = {
            'email': 'test@example.com',
            'password': 'testpass123',
            'name': 'Test Name',
        }
        res = self.client.post(CREATE_USER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(email=payload['email'])
        self.assertTrue(user.check_password(payload['password']))
        self.assertNotIn('password', res.data)

    def test_user_with_email_exists_error(self):
        payload = {
            'email': 'test@example.com',
            'password': 'testpass123',
            'name': 'Test Name',
        }
        create_user(**payload)
        res = self.client.post(CREATE_USER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_password_too_short_error(self):
        payload = {
            'email': 'test@example.com',
            'password': 'pw',
            'name': 'Test Name',
        }
        res = self.client.post(CREATE_USER_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        user_exists = get_user_model().objects.filter(
            email=payload['email']
            ).exists()
        self.assertFalse(user_exists)

    def test_authenticate_token_for_user(self):
        user_details = {
            'email': 'test@example.com',
            'name': 'test_user',
            'password': 'test-user-password123'
        }
        user = create_user(**user_details)

        token_string, PAT = PersonalAccessToken.objects.create(
            user=user,
            name="Test_Token",
        )
        self.client.credentials(HTTP_AUTHORIZATION='PAT ' + token_string)
        res = self.client.get(TOKEN_URL)

        self.assertEqual(res.status_code, status.HTTP_200_OK)

    def test_authenticate_fake_token_fails(self):
        user_details = {
            'email': 'test@example.com',
            'name': 'test_user',
            'password': 'test-user-password123'
        }
        user = create_user(**user_details)

        token_string, PAT = PersonalAccessToken.objects.create(
            user=user,
            name="Test_Token",
        )
        self.client.credentials(HTTP_AUTHORIZATION='PAT ' + "FAKE_TOKEN")
        res = self.client.get(TOKEN_URL)

        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_authenticate_expired_token_fails(self):
        user_details = {
            'email': 'test@example.com',
            'name': 'test_user',
            'password': 'test-user-password123'
        }
        user = create_user(**user_details)

        token_string, PAT = PersonalAccessToken.objects.create(
            user=user,
            name="Test_Token",
            expires=date(2023, 8, 1)
        )
        self.client.credentials(HTTP_AUTHORIZATION='PAT ' + token_string)
        res = self.client.get(TOKEN_URL)
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)
        PAT.refresh_from_db()
        self.assertTrue(PAT.is_expired)

    def test_retrieve_user_unauthorized(self):
        res = self.client.get(ME_URL)

        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)


class PrivateUserPATApiTests(TestCase):

    def setUp(self):
        user_details = {
            'email': 'test@example.com',
            'name': 'test_user',
            'password': 'test-user-password123'
        }
        self.user = create_user(**user_details)
        token_string, self.PAT = PersonalAccessToken.objects.create(
            user=self.user,
            name="test_token"
        )
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION='PAT ' + token_string)


    def test_retrieve_profile_success(self):
        res = self.client.get(ME_URL)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data, {
            'name': self.user.name,
            'email': self.user.email,
        })

    def test_post_me_not_allowed(self):
        res = self.client.post(ME_URL, {})

        self.assertEqual(res.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_update_user_profile(self):
        payload = {'name': 'Updated name', 'password': 'newpasswor123d'}

        res = self.client.patch(ME_URL, payload)
        self.user.refresh_from_db()
        self.assertEqual(self.user.name, payload['name'])
        self.assertTrue(self.user.check_password(payload['password']))
        self.assertEqual(res.status_code, status.HTTP_200_OK)


class PrivateUserJWTApiTests(TestCase):
    """Test JWT Auth for frontend Use"""
    def setUp(self):
        self.client = APIClient()

    def test_get_JWT_token(self):
        """Test getting a JWT token"""
        user_details = {
            'email': 'test@example.com',
            'name': 'test_user',
            'password': 'test-user-password123'
        }
        user = create_user(**user_details)
        key = settings.FERNET_SECRET_KEY.encode()
        cipher_suite = Fernet(key)
        plaintext = user_details['password'].encode("utf-8")
        encrypted = cipher_suite.encrypt(plaintext).decode('utf-8')
        payload = {
            'email': user_details['email'],
            'encrypted_password': encrypted,
        }

        res = self.client.post(AUTHTOKEN_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn('refresh', res.data)
        self.assertIn('access', res.data)
