"""
Database Models
"""
from django.conf import settings
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin
)

from django.utils.crypto import get_random_string
from django.contrib.auth.hashers import make_password

from datetime import date

import uuid
import os


def recipe_image_file_path(instance, filename):
    """Generate file path for new recipe image"""
    ext = os.path.splitext(filename)[1]
    filename = f'{uuid.uuid4()}{ext}'

    return os.path.join('uploads', 'recipe', filename)


class UserManager(BaseUserManager):

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required.")
        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save(using=self.db)

        return user

    def create_superuser(self, email, password):
        user = self.create_user(email, password)
        user.is_staff = True
        user.is_superuser = True

        user.save(using=self._db)

        return user


class User(AbstractBaseUser, PermissionsMixin):

    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'


class PersonalAccessTokenManager(models.Manager):

    def generateToken(self):
        """Generate 32 byte token"""
        return get_random_string(32)

    def generateTokenHash(self, token_string):
        """Hash token to store in DataBase"""
        return make_password(token_string)

    def create(self, user, name, **extra_fields):
        """Create Personal Access Token"""
        if not name:
            raise ValueError('Name is required')

        token_string = self.generateToken()
        token_hash = self.generateTokenHash(token_string)
        PAT = self.model(user=user,
                         name=name,
                         token=token_hash,
                         **extra_fields)

        PAT.save(using=self.db)

        return token_string, PAT

    def checkExpiration(self, token):
        """Check to make sure the token is not expired"""
        if token.expires is None:
            return True
        elif token.expires > date.today():
            return True
        else:
            token.is_expired = True
            token.save()
            return False


class PersonalAccessToken(models.Model):

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )
    token = models.CharField(max_length=88)
    name = models.CharField(max_length=50)
    created = models.DateField(auto_now=False, auto_now_add=True)
    expires = models.DateField(auto_now=False, auto_now_add=False, null=True)
    revoked = models.BooleanField(default=False)
    is_expired = models.BooleanField(default=False)


    objects = PersonalAccessTokenManager()

    def __str__(self):
        return self.name


class Recipe(models.Model):

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    time_minutes = models.IntegerField()
    price = models.DecimalField(max_digits=5, decimal_places=2)
    link = models.CharField(max_length=255, blank=True)
    tags = models.ManyToManyField('Tag')
    ingredients = models.ManyToManyField('Ingredient')
    image = models.ImageField(null=True, upload_to=recipe_image_file_path)

    def __str__(self):
        return self.title


class Tag(models.Model):
    """Tag for Filtering recipes"""
    name = models.CharField(max_length=255)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )

    def __str__(self):
        return self.name


class Ingredient(models.Model):
    name = models.CharField(max_length=255)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )

    def __str__(self):
        return self.name
