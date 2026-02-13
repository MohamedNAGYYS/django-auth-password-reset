from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager

class UserManager(BaseUserManager):
    def create_user(self, email, first_name, last_name, password=None):
        if not email:
            raise ValueError('Users must have an email address.')
        
        email = self.normalize_email(email) # To make it as a real email, not like 'name@GMAIL.COM, name@EXAMPLE.COM'
        user = self.model(email=email, first_name=first_name, last_name=last_name) # I introduce user
        user.set_password(password) # I hash my password
        user.save(using=self._db)
        return user


# Create User class (firstname, lastname, email, password)
class Users(AbstractUser):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    objects = UserManager() # Use my UserManager class

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def __str__(self):
        return self.email
    