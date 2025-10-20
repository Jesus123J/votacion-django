from django.urls import path, include

urlpatterns = [
    path("api/", include("dni_checker.urls")),
]
