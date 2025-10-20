from django.urls import path
from .views import (
    verificar_dni,
    verificar_foto,
    login_dni,
    guardar_voto,
    webauthn_register_options,
    webauthn_register_verify,
    webauthn_authenticate_options,
    webauthn_authenticate_verify,
)
from .extra_views import (
    perudevs_lookup,
    phone_send_otp,
    phone_verify_otp,
    address_fetch,
)

urlpatterns = [
    path("dni/", verificar_dni, name="verificar_dni"),
    path("face-verify/", verificar_foto, name="verificar_foto"),
    path("login-dni/", login_dni, name="login_dni"),
    # WebAuthn
    path("webauthn/register/options/", webauthn_register_options, name="webauthn_register_options"),
    path("webauthn/register/verify/", webauthn_register_verify, name="webauthn_register_verify"),
    path("webauthn/authenticate/options/", webauthn_authenticate_options, name="webauthn_authenticate_options"),
    path("webauthn/authenticate/verify/", webauthn_authenticate_verify, name="webauthn_authenticate_verify"),
    path("guardar_voto/", guardar_voto, name="guardar_voto"),
    # Nuevos endpoints
    path("perudevs/lookup/", perudevs_lookup, name="perudevs_lookup"),
    path("phone/send-otp/", phone_send_otp, name="phone_send_otp"),
    path("phone/verify-otp/", phone_verify_otp, name="phone_verify_otp"),
    path("address/fetch/", address_fetch, name="address_fetch"),
]
