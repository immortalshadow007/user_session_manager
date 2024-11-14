from rest_framework import serializers
from .models import Session, UserAction

class SessionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Session
        fields = ['uid', 'session_token', 'created_at', 'expires_at', 'is_active']

class UserActionSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAction
        fields = ['uid', 'action', 'timestamp', 'details']
