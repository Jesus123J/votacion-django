from django.urls import path
from . import views

urlpatterns = [
    path('health/', views.health_check, name='health-check'),
    path('tasks/', views.TaskListCreateView.as_view(), name='task-list'),
    path('tasks/<int:pk>/', views.TaskDetailView.as_view(), name='task-detail'),
    path('user/', views.user_profile, name='user-profile'),
    path('credentials/', views.ExternalApiCredentialListCreateView.as_view(), name='credential-list-create'),
    path('credentials/<int:pk>/', views.ExternalApiCredentialDetailView.as_view(), name='credential-detail'),
    path('logs/', views.ApiCommunicationLogListView.as_view(), name='log-list'),
]
