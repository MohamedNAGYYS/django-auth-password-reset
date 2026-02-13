from rest_framework import serializers
from .models import Users
from django.contrib.auth import password_validation
import secrets
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str


class RegisterSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)
    class Meta:
        model = Users
        fields = ['first_name', 'last_name', 'email', 'password1', 'password2']

    def validate(self, data):
        if data['password1'] != data['password2']: # If they are not match
            raise serializers.ValidationError('Passwords do not match.') # Hit users with that error
        
        password_validation.validate_password(data['password1']) # Check if password follows the rules that are in settings, otherwise hit users with an error
        return data

    def create(self, validated_data):
        password = validated_data['password1'] # Get a password of (password 1&2) insdie password var

        validated_data.pop('password1') # Remove password 1 from validated data, I got it inside password
        validated_data.pop('password2') # Remove password 2 from validated data, I got it inside password

        # Create user
        user = Users.objects.create_user(
            email=validated_data['email'], # Email = email coming from validated_data
            first_name = validated_data['first_name'], # firstname = first name coming from validated_data
            last_name=validated_data['last_name'], # last name = lastname coming from validated_data
            password=password # password = password coming from validated_data
        )

        return user
    

# Login:
# Display email and password
# Check password
class LoginSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    class Meta:
        model = Users
        fields = ['email', 'password']
 

# Forget Password Serializer:
# Create token for user
# Send to that email user typed
# Check the id and the token when user clicks on it
class ForgetPasswordSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    
    class Meta:
        model = Users
        fields = ['email']


    # I check if email already exists
    def validate(self, data):
        if not Users.objects.filter(email=data['email']).exists():
            raise serializers.ValidationError('Email not found.')
        return data
    
    # I create the reset link
    def create_reset(self, user):
        reset_token = secrets.token_urlsafe(30) # Generate a random token
        uid = urlsafe_base64_encode(force_bytes(user.id)) # I encode user id
        reset_link = f"https://passwordreset.com/{uid}/{reset_token}" # I create a link so user clicks to type a new password
        return reset_link, reset_token
    
    # I deliver reset link
    def send_reset_email(self, user, reset_link):
        send_mail(
            subject='Password Reset',
            message=f"Click here to reset your password: {reset_link}",
            from_email=f"Noneofyourbusiness@example.com",
            recipient_list=[user.email]
        )
    
    def validate_reset(self, uidb64, token, stored_token):
        user_id = force_str(urlsafe_base64_decode(uidb64))

        if token == stored_token:
            return True
        else:
            raise serializers.ValidationError('Invalid or expired token.')
        
# My Notes
"""

ForgetPasswordSerializer:

validate():
I check if email not found, if it is not raise a validation error

create_reset():
secrets.token_urlsafe(30) = It creates random token with strings
urlsafe_base64_encode(force_bytes(id)) = Here It encodes an id like 1 --> PIY32
- I create a random token
- I encode the id
- I create a link and pass my encoded id and reset token
- I return

send_reset_email():
I send an email using:
 send_main(subject=The title, message= I type any message, from_email=The email I am using to send, recipient_list=[here i type the emails I want to send a msg to])

 
validate_reset():
- I check if my token == user's token or not, if true then let them create a new password.

"""