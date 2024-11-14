import uuid
import pytz
import jwt
import os
import base64
import hashlib
import threading
import logging as log
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.conf import settings
from mongoengine import *
from datetime import datetime, timedelta, timezone
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Initialize logging
logger = log.getLogger(__name__)

# Define the MongoEngine Document for the user profile
class Address(EmbeddedDocument):
    street = StringField()
    city = StringField()
    state = StringField()
    zip_code = StringField()
    country = StringField()

class UserProfile(Document):
    UID = StringField(primary_key=True)
    mobile_number_encrypted = StringField(required=True)
    mobile_number_hash = StringField(required=True)
    First_name = StringField(required=False, default="")
    Last_name = StringField(required=False, default="")
    gender = StringField(required=False, default="")
    alternate_mobile_number = StringField(required=False, default="")
    email = EmailField(default="", null=True)
    addresses = ListField(EmbeddedDocumentField(Address))
    profile_picture_url = StringField(default="")
    createdAt = DateTimeField(default=datetime.now(pytz.utc))
    updatedAt = DateTimeField(default=datetime.now(pytz.utc))
    account_status = StringField(default="active")
    last_login = DateTimeField()

    meta = {
        'db_alias': 'user_profile_db',
        'collection': 'User_Profile_db',
        'indexes': [
            {
                'fields': ['createdAt', 'mobile_number_hash', 'account_status'],
            }
        ]
    }


    @classmethod
    def generate_custom_user_id(cls):
        """
        Generates a custom unique user ID.
        """
        prefix = "ELW"
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        random_part = uuid.uuid4().hex[:8].upper()
        custom_user_id = f"{prefix}-{timestamp}-{random_part}"
        return custom_user_id
    
    @classmethod
    def encrypt_mobile_number(cls, field, encryption_key):
        """
        Encrypt the mobile number using AES-256 encryption.
        """
        iv = os.urandom(16)  # Generate a random initialization vector
        cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_mobile_number = encryptor.update(field.encode()) + encryptor.finalize()
        return base64.b64encode(iv + encrypted_mobile_number).decode('utf-8')

    @classmethod
    def store_encryption_key(cls, key_name, encryption_key, expiry_at=None):
        try:
            kv_uri = os.getenv("AZURE_KEY_VAULT_URI")
            credential = DefaultAzureCredential()
            client = SecretClient(vault_url=kv_uri, credential=credential)

            # Convert encryption_key to hex if it's in bytes
            if isinstance(encryption_key, bytes):
                encryption_key = encryption_key.hex()

            # Store with expiry for TPMDocument, without expiry for UserProfile
            if expiry_at:
                client.set_secret(key_name, encryption_key, expires_on=expiry_at)
            else:
                client.set_secret(key_name, encryption_key)
        except Exception as e:
            logger.error(f"Failed to store encryption key: {str(e)}")
            raise Exception(f"Failed to store encryption key: {str(e)}")

    @classmethod
    def hash_mobile_number(cls, mobile_number):
        """
        Hash the mobile number using SHA-256 for secure lookups.
        """
        return hashlib.sha256(mobile_number.encode()).hexdigest()
    
    @classmethod
    def create_user_profile(cls, mobile_number):
        # Now mobile_number is the decrypted mobile number
        if not mobile_number:
            logger.error("Mobile number is None, cannot create user profile.")
            raise ValueError("Mobile number is required to create a user profile.")

        # Hash the mobile number
        mobile_number_hashed = cls.hash_mobile_number(mobile_number)
        
        # Encrypt the mobile number
        encryption_key = os.urandom(32)  # Generate a new encryption key for UserProfile encryption
        encrypted_mobile_number = cls.encrypt_mobile_number(mobile_number, encryption_key)

        # Create custom UUID
        custom_uuid = cls.generate_custom_user_id()

        # create the document
        user_profile = cls(
            UID=custom_uuid,
            mobile_number_encrypted=encrypted_mobile_number,
            mobile_number_hash=mobile_number_hashed,
            createdAt=datetime.now(timezone.utc),
            updatedAt=datetime.now(timezone.utc),
            last_login=datetime.now(timezone.utc),
            account_status="active" 
        )

        # Store the document and encryption key asynchronously
        def store_data():
            try:
                # Store encryption key in the key vault
                key_name = f"encryption-key-{custom_uuid}"
                cls.store_encryption_key(key_name, encryption_key)

                # Save the UserProfile document in the database
                user_profile.save()
            except Exception as e:
                logger.error(f"Failed to store UserProfile: {str(e)}")
                raise

        # Run the store_data function in a separate thread
        store_thread = threading.Thread(target=store_data)
        store_thread.start()

        return user_profile

# Define the Django ORM model for session management
class Session(Document):
    uid = StringField(max_length=50)
    session_token = StringField(max_length=500, unique=True)
    created_at = DateTimeField(auto_now_add=True)
    expires_at = DateTimeField()
    is_active = BooleanField(default=True)

    meta = {
        'db_alias': 'verification_db',
        'collection': 'verification_sessions',
        'indexes': [
            {'fields': ['expires_at'], 'expireAfterSeconds': 0},
            {
                'fields': ['is_active'],
            },
        ]
    }

    def __str__(self):
        return f"Session for UID {self.uid}"

    # Method to create a new session
    @classmethod
    def create_session(cls, uid):
        """
        Create a new session with a TTL for auto-expiration and return the session.
        """
        expires_in = timedelta(minutes=1440)
        expires_at = datetime.now(timezone.utc) + expires_in
        
        session_token = cls.generate_jwt_token(uid, expires_at)

        # Create session record
        session = cls(
            uid=uid,
            session_token=session_token,
            expires_at=expires_at,
            is_active=True
        )
        session.save()
        return session

    @staticmethod
    def generate_jwt_token(uid, expires_at):
        """
        Generate a JWT token with an expiry time.
        """
        now_timestamp = int(datetime.now(timezone.utc).timestamp())
        exp_timestamp = int(expires_at.timestamp())
        payload = {
            'uid': uid,
            'exp': exp_timestamp,
            'iat': now_timestamp,
        }
        return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS256')

    # Method to validate a session token
    @staticmethod
    def validate_session(token):
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=['HS256'])
            uid = payload['uid']
            # Check if session exists and is active
            session = Session.objects.get(session_token=token, uid=uid, is_active=True)
            return session
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, Session.DoesNotExist):
            return None

    # Method to terminate a session
    def terminate(self):
        self.is_active = False
        self.save()
        self.delete()

# Define the model for user action monitoring
class UserAction(models.Model):
    uid = models.CharField(max_length=50)
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.JSONField(null=True, blank=True)

    def __str__(self):
        return f"Action by UID {self.uid}: {self.action} at {self.timestamp}"
