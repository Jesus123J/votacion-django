from django.db import models
import secrets
from django.utils import timezone
from datetime import timedelta


def _expires_default():
    """Retorna una fecha de expiración amplia (10 años). Usado como default en migraciones."""
    return timezone.now() + timedelta(days=3650)


class DNIToken(models.Model):
    """Token no-expirable asociado a un DNI."""
    dni = models.CharField(max_length=16, unique=True)
    token = models.CharField(max_length=128, unique=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    # En algunas bases ya existe esta columna con NOT NULL; la incluimos en el modelo
    # y la poblamos al emitir para evitar IntegrityError.
    expires_at = models.DateTimeField(default=_expires_default)

    @staticmethod
    def issue_for(dni: str) -> "DNIToken":
        try:
            instance = DNIToken.objects.get(dni=dni)
            changed = False
            if not getattr(instance, "token", None):
                instance.token = secrets.token_urlsafe(48)
                changed = True
            if not getattr(instance, "expires_at", None):
                instance.expires_at = timezone.now() + timedelta(days=3650)
                changed = True
            if changed:
                instance.save(update_fields=["token", "expires_at"])  # guarda solo los campos ajustados
            return instance
        except DNIToken.DoesNotExist:
            # Crear explícitamente con todos los campos poblados para evitar NULLs
            return DNIToken.objects.create(
                dni=dni,
                token=secrets.token_urlsafe(48),
                expires_at=timezone.now() + timedelta(days=3650),
            )

    def __str__(self) -> str:
        return f"DNIToken(dni={self.dni})"


class WebAuthnCredential(models.Model):
    """
    Credencial WebAuthn asociada a un usuario identificado por DNI.
    Nota: Para producción, validar attestation y assertions con una librería WebAuthn.
    """
    dni = models.CharField(max_length=16, db_index=True)
    user_handle = models.CharField(max_length=128)  # normalmente un id estable por usuario
    credential_id = models.CharField(max_length=512, unique=True)
    public_key = models.TextField()  # base64url u otro formato serializado
    sign_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"WebAuthnCredential(dni={self.dni}, cred={self.credential_id[:12]}...)"


#guardar votos
class Voto(models.Model):
    id = models.AutoField(primary_key=True, db_column='id_voto')
    dni= models.CharField(db_column='id_usuario', max_length=16)
    partido = models.CharField(db_column='partido_politico', max_length=100)
    nombre = models.CharField(db_column='nombre_candidato', max_length=100)
    ts = models.BigIntegerField(db_column='fecha_voto')
    hash_voto = models.TextField()

    class Meta:
        managed = False  # Importante: Django no intentará crear ni modificar esta tabla
        db_table = "votos"  #  Nombre exacto de la tabla que ya tienes en tu base


class Persona(models.Model):
    """Perfil básico del ciudadano obtenido desde PeruDevs API."""
    dni = models.CharField(max_length=16, unique=True)
    nombres = models.CharField(max_length=255)
    apellido_paterno = models.CharField(max_length=255)
    apellido_materno = models.CharField(max_length=255)
    nombre_completo = models.CharField(max_length=512)
    genero = models.CharField(max_length=2, blank=True)
    fecha_nacimiento = models.CharField(max_length=32, blank=True)
    codigo_verificacion = models.CharField(max_length=8, blank=True)
    distrito = models.CharField(max_length=255, blank=True)
    raw_json = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"Persona(dni={self.dni}, distrito={self.distrito})"


class PhoneOTP(models.Model):
    """Registro de verificación por SMS."""
    dni = models.CharField(max_length=16, db_index=True)
    phone = models.CharField(max_length=32)
    otp = models.CharField(max_length=8)
    verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"PhoneOTP(dni={self.dni}, phone={self.phone}, verified={self.verified})"


class VotoDistrito(models.Model):
    """Tabla propia para contar/guardar votos por distrito."""
    dni = models.CharField(max_length=16)
    distrito = models.CharField(max_length=255)
    partido = models.CharField(max_length=100)
    nombre = models.CharField(max_length=100)
    ts = models.BigIntegerField()
    hash_voto = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["distrito"]),
            models.Index(fields=["dni"]),
        ]

    def __str__(self) -> str:
        return f"VotoDistrito(dni={self.dni}, distrito={self.distrito}, partido={self.partido}, nombre={self.nombre})"