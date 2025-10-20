#!/bin/bash

# Esperar a que la base de datos esté disponible
echo "Esperando a la base de datos..."
while ! nc -z $DB_HOST $DB_PORT; do
  sleep 1
done
echo "Base de datos disponible!"

# Ejecutar migraciones
echo "Ejecutando migraciones..."
python manage.py migrate

# Crear superusuario si no existe
echo "Creando superusuario..."
python manage.py shell -c "
from django.contrib.auth.models import User
import os
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@example.com', os.getenv('DJANGO_SUPERUSER_PASSWORD', 'admin123'))
    print('Superusuario creado')
else:
    print('Superusuario ya existe')
"

# Recopilar archivos estáticos
echo "Recopilando archivos estáticos..."
python manage.py collectstatic --noinput

# Iniciar servidor
echo "Iniciando servidor Django..."
exec gunicorn --bind 0.0.0.0:8000 --workers 4 myproject.wsgi:application
