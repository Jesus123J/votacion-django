from django.db import models
from django.contrib.auth.models import User

class Task(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    completed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tasks')

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title


class ExternalApiCredential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='external_api_credentials')
    api_name = models.CharField(max_length=100)
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=255)  # Se recomienda encriptar este campo
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'api_name')
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.user.username} - {self.api_name}'


class ApiCommunicationLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='api_logs')
    request_url = models.URLField()
    request_method = models.CharField(max_length=10)
    request_headers = models.TextField(blank=True)
    request_body = models.TextField(blank=True)
    response_status_code = models.PositiveIntegerField()
    response_body = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f'{self.request_method} {self.request_url} - {self.response_status_code}'
