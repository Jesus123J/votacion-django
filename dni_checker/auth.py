from typing import Optional, Tuple

from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.exceptions import AuthenticationFailed

from .models import DNIToken


class DNITokenAuthentication(BaseAuthentication):
    """
    Autenticación por token propio (no expira) emitido por DNI.
    Acepta: Authorization: DNI <dni_token>
    """

    keyword = b"dni"

    def authenticate(self, request) -> Optional[Tuple[object, str]]:
        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != self.keyword:
            return None
        if len(auth) != 2:
            raise AuthenticationFailed("Invalid Authorization header")

        token = auth[1].decode("utf-8")
        try:
            dni_token = DNIToken.objects.get(token=token)
        except DNIToken.DoesNotExist:
            raise AuthenticationFailed("Invalid DNI token")

        # Creamos/obtenemos un usuario de aplicación para marcar autenticado
        User = get_user_model()
        username = f"dni_{dni_token.dni}"
        user, _ = User.objects.get_or_create(username=username, defaults={"is_active": True})
        return (user, token)
