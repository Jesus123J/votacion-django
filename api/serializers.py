from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Task, ExternalApiCredential, ApiCommunicationLog

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email']

class TaskSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = Task
        fields = ['id', 'title', 'description', 'completed', 'created_at', 'updated_at', 'user']
        
    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class ExternalApiCredentialSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    password = serializers.CharField(write_only=True)

    class Meta:
        model = ExternalApiCredential
        fields = ['id', 'api_name', 'username', 'password', 'created_at', 'updated_at', 'user']
        read_only_fields = ['created_at', 'updated_at', 'user']

    def create(self, validated_data):
        validated_data['user'] = self.context['request'].user
        # En un entorno de producción, la contraseña debe ser encriptada.
        # Ejemplo: from django.contrib.auth.hashers import make_password
        # validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)


class ApiCommunicationLogSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)

    class Meta:
        model = ApiCommunicationLog
        fields = '__all__'
