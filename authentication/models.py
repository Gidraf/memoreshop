import jwt

from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth.models import (
    AbstractBaseUser, BaseUserManager, PermissionsMixin
)
from django.core.validators import RegexValidator
from django.db import models


class UserManager(BaseUserManager):
    """
    Create a customuser model
    """

    def create_user(self, username, phone, email, password=None):
        """Create and return a `User` with an email, username and password."""
        if username is None:
            raise TypeError('Users must have a username.')

        if email is None:
            raise TypeError('Users must have an email address.')

        if phone is None:
            raise TypeError('Users must have phonenumber')

        user = self.model(username=username, phone=phone, email=self.normalize_email(email))
        user.set_password(password)
        user.save()

        return user

    def create_superuser(self, username, phone, email, password):
        """
        Create and return a `User` with superuser powers.

        Superuser powers means that this use is an admin that can do anything
        they want.
        """
        if password is None:
            raise TypeError('Superusers must have a password.')

        user = self.create_user(username, phone, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()

        return user


class User(AbstractBaseUser, PermissionsMixin):

    reval = RegexValidator(
        r'^[0-9a-zA-Z]*$',
        'Username should only contain alphanumeric characters')
    username = models.CharField(
        db_index=True,
        max_length=255,
        unique=True,
        validators=[reval])

    email = models.EmailField(db_index=True, unique=True)

    phone = models.IntegerField(db_index=True, unique=True)

    is_active = models.BooleanField(default=True)

    is_staff = models.BooleanField(default=False)

    is_confirmed_email = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        """
        Returns a string representation of this `User`.

        This string is used when a `User` is printed in the console.
        """
        return self.email

    def token(self):
        return self.encode_auth_token()

    def encode_auth_token(self):
        """
        Create payload and use it to generate JWT token
        :return: encoded token
        """
        payload = {
            'exp': datetime.utcnow() + timedelta(days=7),
            'iat': datetime.utcnow(),
            'id': self.pk,
        }

        tk = jwt.encode(payload, settings.SECRET_KEY, 'HS256')
        return tk.decode()


@property
def get_full_name(self):
    """
    This method is required by Django for things like handling emails.
    Typically, this would be the user's first and last name. Since we do
    not store the user's real name, we return their username instead.
    """
    return self.username


def get_short_name(self):
    """
    This method is required by Django for things like handling emails.
    Typically, this would be the user's first name. Since we do not store
    the user's real name, we return their username instead.
    """
    return self.username
