import json
import secrets
import requests
from django.http import JsonResponse
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from .models import Persona, PhoneOTP
import re


def _fetch_and_store_perudevs(dni: str, key: str) -> Persona:
    url = "https://api.perudevs.com/api/v1/dni/complete"
    params = {"document": dni, "key": key}
    resp = requests.get(url, params=params, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    res = data.get('resultado') or {}
    persona, _ = Persona.objects.update_or_create(
        dni=res.get('id') or dni,
        defaults={
            'nombres': res.get('nombres', ''),
            'apellido_paterno': res.get('apellido_paterno', ''),
            'apellido_materno': res.get('apellido_materno', ''),
            'nombre_completo': res.get('nombre_completo', ''),
            'genero': res.get('genero', ''),
            'fecha_nacimiento': res.get('fecha_nacimiento', ''),
            'codigo_verificacion': res.get('codigo_verificacion', ''),
            'raw_json': data,
        }
    )
    return persona


def _normalize_phone(p: str) -> str:
    """Normaliza teléfonos a formato E.164 sencillo.
    - Si ya viene en +E.164 (7-15 dígitos): devuelve tal cual.
    - Si es móvil peruano de 9 dígitos iniciando en 9: antepone +51.
    - Si son sólo dígitos (7-15): antepone +.
    - Caso contrario, retorna cadena vacía (inválido).
    """
    p = (p or "").strip()
    p2 = re.sub(r"[\s\-()]+", "", p)
    if p2.startswith('+'):
        return p2 if re.fullmatch(r"\+\d{7,15}", p2) else ""
    if re.fullmatch(r"9\d{8}", p2):
        return "+51" + p2
    if re.fullmatch(r"\d{7,15}", p2):
        return "+" + p2
    return ""


@api_view(["POST"])  # { dni }
@permission_classes([AllowAny])
def perudevs_lookup(request):
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"error": "JSON inválido"}, status=400)
    dni = (payload.get("dni") or "").strip()
    if not dni:
        return JsonResponse({"error": "dni requerido"}, status=400)
    key = getattr(settings, 'PERUDEVS_KEY', None)
    if not key:
        return JsonResponse({"error": "Configura PERUDEVS_KEY en settings/.env"}, status=500)
    try:
        persona = _fetch_and_store_perudevs(dni, key)
        return JsonResponse({
            "ok": True,
            "persona": {
                "dni": persona.dni,
                "nombres": persona.nombres,
                "apellido_paterno": persona.apellido_paterno,
                "apellido_materno": persona.apellido_materno,
                "nombre_completo": persona.nombre_completo,
                "genero": persona.genero,
                "fecha_nacimiento": persona.fecha_nacimiento,
                "codigo_verificacion": persona.codigo_verificacion,
                "distrito": persona.distrito,
            }
        })
    except requests.RequestException as e:
        return JsonResponse({"error": f"HTTP error: {e}"}, status=502)


@api_view(["POST"])  # { dni, phone }
@permission_classes([AllowAny])
def phone_send_otp(request):
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"error": "JSON inválido"}, status=400)
    dni = (payload.get("dni") or "").strip()
    phone = (payload.get("phone") or "").strip()
    if not dni or not phone:
        return JsonResponse({"error": "dni y phone requeridos"}, status=400)

    phone_norm = _normalize_phone(phone)
    if not phone_norm:
        return JsonResponse({"error": "Número de teléfono inválido. Use formato internacional, ej: +51999999999"}, status=400)

    otp = f"{secrets.randbelow(1000000):06d}"
    tw_sid = getattr(settings, 'TWILIO_ACCOUNT_SID', None)
    tw_token = getattr(settings, 'TWILIO_AUTH_TOKEN', None)
    tw_from = getattr(settings, 'TWILIO_FROM', None)
    if not (tw_sid and tw_token and tw_from):
        return JsonResponse({"error": "Configura TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM"}, status=500)
    try:
        # Lazy import to avoid hard dependency during migrations/startup
        from twilio.rest import Client as TwilioClient
        from twilio.base.exceptions import TwilioRestException
        client = TwilioClient(tw_sid, tw_token)
        client.messages.create(body=f"Tu código de verificación es: {otp}", from_=tw_from, to=phone_norm)
        PhoneOTP.objects.create(dni=dni, phone=phone_norm, otp=otp, verified=False)
        return JsonResponse({"ok": True})
    except ModuleNotFoundError:
        return JsonResponse({"error": "Twilio no está instalado. Ejecuta 'pip install twilio' o 'pip install -r requirements.txt'"}, status=500)
    except TwilioRestException as e:
        # Mapear errores comunes de Twilio a mensajes claros
        code = getattr(e, 'code', None)
        msg = str(e)
        if code == 21211:
            return JsonResponse({"error": "Número destino inválido. Use formato internacional, ej: +51999999999"}, status=400)
        if code == 21608 or 'unverified' in msg.lower():
            return JsonResponse({
                "error": "Tu cuenta de Twilio es de prueba: verifica el número destino en Twilio o actualiza la cuenta para enviar a números no verificados."
            }, status=400)
        return JsonResponse({"error": msg}, status=502)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=502)


@api_view(["POST"])  # { dni, phone, otp }
def phone_verify_otp(request):
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"error": "JSON inválido"}, status=400)
    dni = (payload.get("dni") or "").strip()
    phone = (payload.get("phone") or "").strip()
    otp = (payload.get("otp") or "").strip()
    if not dni or not phone or not otp:
        return JsonResponse({"error": "dni, phone y otp requeridos"}, status=400)
    phone_norm = _normalize_phone(phone)
    if not phone_norm:
        return JsonResponse({"error": "Número de teléfono inválido. Use formato internacional, ej: +51999999999"}, status=400)
    rec = PhoneOTP.objects.filter(dni=dni, phone=phone_norm).order_by('-created_at').first()
    if not rec:
        return JsonResponse({"ok": False, "error": "Código incorrecto"}, status=400)
    if rec.verified:
        return JsonResponse({"ok": True})
    if rec.otp != otp:
        return JsonResponse({"ok": False, "error": "Código incorrecto"}, status=400)
    rec.verified = True
    rec.save(update_fields=["verified"])
    return JsonResponse({"ok": True})


@api_view(["POST"])  # { dni }
@permission_classes([AllowAny])
def address_fetch(request):
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"error": "JSON inválido"}, status=400)
    dni = (payload.get("dni") or "").strip()
    if not dni:
        return JsonResponse({"error": "dni requerido"}, status=400)
    bearer = getattr(settings, 'DIRECCION_API_BEARER', None)
    base = getattr(settings, 'DIRECCION_API_BASE', 'https://miapi.cloud')
    if not bearer:
        return JsonResponse({"error": "Configura DIRECCION_API_BEARER en settings/.env"}, status=500)
    url = f"{base}/v1/dni/{dni}"
    try:
        resp = requests.get(url, headers={"Authorization": f"Bearer {bearer}"}, timeout=20)
        if not resp.ok:
            return JsonResponse({"error": resp.text}, status=resp.status_code)
        data = resp.json()
        distrito = (
            data.get('distrito') or (data.get('direccion', {}).get('distrito') if isinstance(data.get('direccion'), dict) else None)
        ) or ''
        Persona.objects.update_or_create(
            dni=dni,
            defaults={
                'distrito': distrito,
                'raw_json': data,
            }
        )
        return JsonResponse({"ok": True, "distrito": distrito, "raw": data})
    except requests.RequestException as e:
        return JsonResponse({"error": f"HTTP error: {e}"}, status=502)
