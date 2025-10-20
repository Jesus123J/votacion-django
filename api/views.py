from rest_framework import generics, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.contrib.auth.models import User
from .models import Task, ExternalApiCredential, ApiCommunicationLog
from .serializers import TaskSerializer, UserSerializer, ExternalApiCredentialSerializer, ApiCommunicationLogSerializer

@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """Endpoint para verificar que la API está funcionando"""
    return Response({
        'status': 'OK',
        'message': 'API funcionando correctamente'
    })

class TaskListCreateView(generics.ListCreateAPIView):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return Task.objects.filter(user=self.request.user)

class TaskDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = TaskSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return Task.objects.filter(user=self.request.user)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    """Obtener información del usuario actual"""
    serializer = UserSerializer(request.user)
    return Response(serializer.data)


class ExternalApiCredentialListCreateView(generics.ListCreateAPIView):
    serializer_class = ExternalApiCredentialSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ExternalApiCredential.objects.filter(user=self.request.user)


class ExternalApiCredentialDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = ExternalApiCredentialSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ExternalApiCredential.objects.filter(user=self.request.user)


class ApiCommunicationLogListView(generics.ListAPIView):
    serializer_class = ApiCommunicationLogSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ApiCommunicationLog.objects.filter(user=self.request.user)
