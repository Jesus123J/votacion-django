import requests
from django.http import JsonResponse
from django.conf import settings
import json
import tempfile
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication
from .auth import DNITokenAuthentication
import os
import re
from .models import DNIToken, WebAuthnCredential
import base64
import secrets
from .models import Voto
from .models import Voto, WebAuthnCredential
from rest_framework.response import Response
from rest_framework import status
from datetime import datetime
from django.views.decorators.csrf import csrf_exempt

"""Views protegidas con JWT del usuario. El servicio internamente usa un token propio para RENIEC."""

def _b64url(b: bytes) -> str:
    """Convierte bytes a base64url sin padding (=)."""
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _get_dni_from_token(request):
    """Obtiene el DNI desde el header Authorization o del usuario autenticado.
    Prioriza Authorization: DNI <token> para resolver el DNI desde la tabla DNIToken.
    Como alternativa, si el autenticador creó un usuario con username "dni_<dni>", lo usa.
    """
    # 1) Intentar extraer del header Authorization
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    parts = auth.split()
    if len(parts) == 2 and parts[0].lower() == "dni":
        token = parts[1]
        try:
            return DNIToken.objects.get(token=token).dni
        except DNIToken.DoesNotExist:
            return None

    # 2) Alternativa: del username si sigue el patrón dni_XXXXXXXX
    username = getattr(request.user, "username", "") or ""
    if username.startswith("dni_"):
        return username[4:]
    return None

@api_view(["POST"])  # typical to use POST to issue options
@authentication_classes([JWTAuthentication, DNITokenAuthentication])
@permission_classes([IsAuthenticated])
def webauthn_register_options(request):
    """Genera opciones de registro WebAuthn y guarda el challenge en sesión.
    Retorna el objeto `publicKey` listo para navigator.credentials.create().
    """
    dni = _get_dni_from_token(request)
    if not dni:
        return JsonResponse({"error": "DNI no encontrado para token"}, status=401)

    # rp.id debe coincidir con el dominio (sin puerto). Para localhost usamos host actual.
    rp_id = request.get_host().split(":")[0]
    rp_name = "Votación"

    # Crear challenge y guardarlo en sesión
    challenge = secrets.token_bytes(32)
    challenge_b64 = _b64url(challenge)
    request.session["webauthn_register_challenge"] = challenge_b64

    # user.id debe ser un ArrayBuffer (aquí lo codificamos en base64url a string)
    user_id_b64 = _b64url(dni.encode("utf-8"))

    options = {
        "publicKey": {
            "challenge": challenge_b64,
            "rp": {"name": rp_name, "id": rp_id},
            "user": {
                "id": user_id_b64,
                "name": dni,
                "displayName": f"Usuario {dni}",
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},   # ES256
                {"type": "public-key", "alg": -257}, # RS256
            ],
            "timeout": 60000,
            "attestation": "none",
            "authenticatorSelection": {
                "userVerification": "required"
            },
        }
    }
    return JsonResponse(options)

@api_view(["GET", "POST"])
@authentication_classes([JWTAuthentication, DNITokenAuthentication])
@permission_classes([IsAuthenticated])
def verificar_dni(request):
    # GET: /api/dni/?numero=XXXXXXXX  |  POST: JSON { "numero": "XXXXXXXX" }
    if request.method == "GET":
        numero = request.GET.get("numero")
    else:
        try:
            payload = json.loads(request.body.decode("utf-8"))
        except Exception:
            return JsonResponse({"error": "JSON inválido"}, status=400)
        numero = payload.get("numero")
    if not numero:
        return JsonResponse({"error": "Número de DNI requerido"}, status=400)

    # Configuración del servicio RENIEC desde settings
    reniec_api = settings.RENEIC_API
    reniec_token = settings.RENEIC_TOKEN

    if not reniec_token:
        return JsonResponse({
            "error": "Token de servicio RENIEC no configurado",
            "hint": "Defina RENEIC_TOKEN en variables de entorno o en settings"
        }, status=500)

    # Intentos con diferentes estilos de autenticación comunes
    ua = "dni-checker/1.0 (+github.com/your-org)"
    base_headers = {"User-Agent": ua}
    attempts = [
        {"headers": {"Authorization": f"Bearer {reniec_token}"}, "params": {}},
        {"headers": {"Authorization": reniec_token}, "params": {}},
        {"headers": {"X-API-Key": reniec_token}, "params": {}},
        {"headers": {"x-api-key": reniec_token}, "params": {}},
        {"headers": {}, "params": {"apikey": reniec_token}},
        {"headers": {}, "params": {"token": reniec_token}},
    ]

    last_resp = None
    last_style = None
    for style in attempts:
        try:
            headers = {**base_headers, **style["headers"]}
            params = {"numero": numero, **style["params"]}
            resp = requests.get(reniec_api, headers=headers, params=params, timeout=20)
        except requests.RequestException as e:
            return JsonResponse({"error": f"Error de red: {str(e)}"}, status=502)

        # Éxito: retornamos
        if resp.ok:
            try:
                data = resp.json()
            except ValueError:
                return JsonResponse({"error": "Respuesta no es JSON"}, status=502)
            return JsonResponse(data, safe=False)

        last_resp = resp
        last_style = style

        # Si es claramente auth/rate-limit, probamos siguiente estilo
        body = (resp.text or "").lower()
        if resp.status_code in (401, 403, 429) or "apikey" in body or "api key" in body:
            continue
        else:
            break

    # Sin éxito tras los intentos: responder con detalle
    status_code = last_resp.status_code if last_resp is not None else 502
    masked = reniec_token[:4] + "***" + reniec_token[-4:] if reniec_token else ""
    return JsonResponse({
        "error": "No se pudo verificar el DNI",
        "status": status_code,
        "details": (last_resp.text[:500] if last_resp is not None else "Sin respuesta"),
        "used_auth_styles": "multiple",
        "token_hint": masked,
    }, status=status_code)

@api_view(["POST"])
@authentication_classes([JWTAuthentication, DNITokenAuthentication])
@permission_classes([IsAuthenticated])
def verificar_foto(request):
    # Espera multipart/form-data con archivos: 'selfie' y 'dni'
    selfie = request.FILES.get("selfie")
    dni = request.FILES.get("dni")

    if not selfie or not dni:
        return JsonResponse({"error": "Se requieren archivos 'selfie' y 'dni'"}, status=400)

    # Validaciones básicas
    if selfie.size == 0 or dni.size == 0:
        return JsonResponse({"error": "Archivos vacíos"}, status=400)
    allowed_types = {"image/jpeg", "image/png", "image/jpg"}
    if (getattr(selfie, 'content_type', None) not in allowed_types) or (getattr(dni, 'content_type', None) not in allowed_types):
        # DeepFace/OpenCV suelen admitir jpg/png; ajustar si se requiere más tipos
        pass

    try:
        # Importar DeepFace en tiempo de ejecución para no romper el servidor si no está instalado
        try:
            from deepface import DeepFace
        except ImportError:
            return JsonResponse({"error": "Dependencia faltante: instale 'deepface' para usar este endpoint"}, status=501)

        # En Windows, usar delete=False y cerrar antes de pasar a OpenCV/DeepFace
        f1 = tempfile.NamedTemporaryFile(suffix=".jpg", delete=False)
        f2 = tempfile.NamedTemporaryFile(suffix=".jpg", delete=False)
        f1_path, f2_path = f1.name, f2.name
        try:
            for chunk in selfie.chunks():
                f1.write(chunk)
            f1.flush()
            f1.close()

            for chunk in dni.chunks():
                f2.write(chunk)
            f2.flush()
            f2.close()

            # DeepFace verifica por path. No lanzar excepción si no detecta rostro.
            result = DeepFace.verify(
                img1_path=f1_path,
                img2_path=f2_path,
                enforce_detection=False,
            )

            # Estandarizar respuesta: verified/distance/threshold
            distance = result.get("distance")
            threshold = result.get("threshold")
            if threshold is None:
                # Umbral por defecto (modelo VGG-Face suele ~0.4)
                threshold = 0.4
            if distance is not None:
                verified_comp = distance <= threshold
            else:
                verified_comp = bool(result.get("verified", False))

            payload = {
                "verified": bool(verified_comp),
                "distance": distance,
                "threshold": threshold,
                "raw": result,
            }
            return JsonResponse(payload)
        finally:
            # Limpiar archivos temporales
            try:
                if os.path.exists(f1_path):
                    os.unlink(f1_path)
            except Exception:
                pass
            try:
                if os.path.exists(f2_path):
                    os.unlink(f2_path)
            except Exception:
                pass
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


# Login por DNI: emite un token propio no-expirable
from rest_framework.permissions import AllowAny
from .models import DNIToken

@api_view(["POST"])
@permission_classes([AllowAny])
def login_dni(request):
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"error": "JSON inválido"}, status=400)
    dni = (payload.get("dni") or "").strip()
    if not re.fullmatch(r"\d{8,12}", dni):
        return JsonResponse({"error": "DNI inválido"}, status=400)

    token_obj = DNIToken.issue_for(dni)
    return JsonResponse({"token": token_obj.token, "dni": dni})


@api_view(["POST"])
@authentication_classes([JWTAuthentication, DNITokenAuthentication])
@permission_classes([IsAuthenticated])
def webauthn_register_verify(request):
    """Recibe attestation response. Para demo, no valida criptográficamente y guarda credencial."""
    dni = _get_dni_from_token(request)
    if not dni:
        return JsonResponse({"error": "DNI no encontrado para token"}, status=401)

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"error": "JSON inválido"}, status=400)

    expected_challenge = request.session.get("webauthn_register_challenge")
    # Para demo: si no hay challenge en sesión (p.ej. cookies bloqueadas), no fallar
    # En producción, validar siempre que clientDataJSON.challenge == expected_challenge

    # Aceptar formato plano o anidado bajo 'response'
    obj = payload
    resp = payload.get("response") or {}
    client_data_json_b64 = obj.get("clientDataJSON") or resp.get("clientDataJSON")
    attestation_object_b64 = obj.get("attestationObject") or resp.get("attestationObject")
    raw_id_b64 = obj.get("rawId") or obj.get("id")

    if not (client_data_json_b64 and attestation_object_b64 and raw_id_b64):
        return JsonResponse({
            "error": "Faltan campos de attestation",
            "need": ["rawId/id", "clientDataJSON", "attestationObject"]
        }, status=400)

    # En un sistema real, verificarías clientData.challenge == expected_challenge y parsearías attestation.
    # Aquí, almacenamos la credencial con datos mínimos.
    cred_id = raw_id_b64
    WebAuthnCredential.objects.update_or_create(
        credential_id=cred_id,
        defaults={
            "dni": dni,
            "user_handle": dni,
            "public_key": "stored-in-attestation-parsing",
            "sign_count": 0,
        },
    )

    # Limpiar challenge si existía
    request.session.pop("webauthn_register_challenge", None)
    return JsonResponse({"ok": True})


@api_view(["POST"])
@authentication_classes([JWTAuthentication, DNITokenAuthentication])
@permission_classes([IsAuthenticated])
def webauthn_authenticate_options(request):
    dni = _get_dni_from_token(request)
    if not dni:
        return JsonResponse({"error": "DNI no encontrado para token"}, status=401)

    creds = WebAuthnCredential.objects.filter(dni=dni)
    if not creds.exists():
        # Evitar 404 para que el frontend pueda reaccionar sin caer en error
        return JsonResponse({"needRegistration": True, "message": "Sin credenciales registradas"}, status=200)

    challenge = secrets.token_bytes(32)
    request.session["webauthn_auth_challenge"] = _b64url(challenge)
    allow = [{"type": "public-key", "id": c.credential_id} for c in creds]
    public_key = {
        "challenge": request.session["webauthn_auth_challenge"],
        "timeout": 60000,
        "rpId": request.get_host().split(":")[0],
        "userVerification": "required",
        "allowCredentials": allow,
    }
    return JsonResponse(public_key)


@api_view(["POST"])
@authentication_classes([JWTAuthentication, DNITokenAuthentication])
@permission_classes([IsAuthenticated])
def webauthn_authenticate_verify(request):
    dni = _get_dni_from_token(request)
    if not dni:
        return JsonResponse({"error": "DNI no encontrado para token"}, status=401)

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"error": "JSON inválido"}, status=400)

    expected_challenge = request.session.get("webauthn_auth_challenge")
    # Para demo: no exigir challenge en sesión si no hay cookies

    # Aceptar formato plano o anidado en response
    obj = payload
    resp = payload.get("response") or {}
    raw_id_b64 = obj.get("rawId")
    authenticator_data_b64 = obj.get("authenticatorData") or resp.get("authenticatorData")
    client_data_json_b64 = obj.get("clientDataJSON") or resp.get("clientDataJSON")
    signature_b64 = obj.get("signature") or resp.get("signature")

    if not (raw_id_b64 and authenticator_data_b64 and client_data_json_b64 and signature_b64):
        return JsonResponse({"error": "Faltan campos de assertion"}, status=400)

    # En un sistema real, verificarías la firma con la public_key almacenada.
    # Aquí aceptamos la assertion y marcamos ok.
    request.session.pop("webauthn_auth_challenge", None)
    return JsonResponse({"ok": True})

#Guardar votos
@csrf_exempt
def guardar_voto(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            dni = data.get('dni')
            partido = data.get('partido')
            #usuario = data.get('usuario')  # si lo agregaste
            nombre = data.get('nombre')

            # ejemplo simple de hash de voto (puedes hacerlo más robusto)
            import hashlib
            hash_voto = hashlib.sha256(f"{dni}{nombre}{partido}".encode()).hexdigest()

            Voto.objects.create(
                dni=dni,
                partido=partido,
                #usuario=usuario,
                hash_voto=hash_voto,
                nombre=nombre
            )
            return JsonResponse({'message': 'Voto guardado correctamente'}, status=201)

        except Exception as e:
            print('❌ Error al guardar voto:', e)
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Método no permitido'}, status=405)