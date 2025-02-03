from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import pyotp
from django.contrib.auth import get_backends
from django.contrib.auth.decorators import login_required
from app.models import UserProfile
from django.views.decorators.csrf import csrf_exempt
import qrcode
import base64
import time
from io import BytesIO
from axes.decorators import axes_dispatch
from django.utils.timezone import now, timedelta
import logging

# Logowanie i rejestracja użytkownika
@axes_dispatch
def login_view(request):
    if request.method == "POST":
        time.sleep(1)

        if request.POST.get("honeypot"): 
            return render(request, 'login.html', {'error': "Podejrzana aktywność wykryta."})

        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user:
            if user.profile.is_totp_locked():
                return render(request, 'login.html', {
                    'error': "Zbyt wiele nieudanych prób. Spróbuj ponownie za 5 minut."
                })
            # Przechowaj ID użytkownika w sesji i przejdź do 2FA
            request.session['user_id'] = user.id
            return redirect('verify_2fa')
        else:
            return render(request, 'login.html', {'error': "Nieprawidłowa nazwa użytkownika lub hasło."})

    return render(request, 'login.html')

def register_view(request):
    if request.method == "POST":
        if request.POST.get("honeypot"):  # Jeśli pole honeypot zostało wypełnione, blokujemy dostęp
            return render(request, 'login.html', {'error': "Podejrzana aktywność wykryta."})

        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")

        if User.objects.filter(username=username).exists():
            return render(request, 'register.html', {'errors': ["Podana nazwa użytkownika jest już zajęta."]})

        if User.objects.filter(email=email).exists():
            return render(request, 'register.html', {'errors': ["E-mail jest już zajęty."]})

        try:
            validate_password(password) 
            user = User.objects.create_user(username=username, email=email, password=password)
            request.session['user_id'] = user.id
            return redirect('setup_2fa')
        except ValidationError as e:
            return render(request, 'register.html', {'errors': e.messages})
    
    return render(request, 'register.html')

def logout_view(request):
    logout(request)
    return redirect('login')

# Dwuetapowa weryfikacja
def setup_2fa_view(request):
    user_id = request.session.get('user_id')
    user = User.objects.get(id=user_id)
    user_profile = user.profile

    # Generowanie sekretu TOTP
    if not user_profile.totp_secret:
        totp_secret = pyotp.random_base32()
        user_profile.totp_secret = user_profile.encrypt_totp_secret(totp_secret)
        user_profile.save()

    # Generowanie kodu QR
    decrypted_totp_secret = user_profile.decrypt_totp_secret()
    if not decrypted_totp_secret:
        return render(request, 'setup_2fa.html', {'error': "Nie udało się odszyfrować sekretu."})

    totp = pyotp.TOTP(decrypted_totp_secret)
    qr_url = totp.provisioning_uri(issuer_name="Custom Twitter", name=user.username)

    qr = qrcode.make(qr_url)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()

    return render(request, 'setup_2fa.html', {'qr_base64': qr_base64})

@axes_dispatch
def verify_2fa_view(request):
    if request.method == "POST":
        user_id = request.session.get('user_id')
        user = User.objects.get(id=user_id)
        user_profile = user.profile

        if user_profile.is_totp_locked():
            return render(request, 'verify_2fa.html', {
                'error': "Zbyt wiele nieudanych prób. Spróbuj ponownie za 5 minut."
            })

        decrypted_totp_secret = user_profile.decrypt_totp_secret()
        if not decrypted_totp_secret:
            return render(request, 'verify_2fa.html', {'error': "Nie udało się odszyfrować sekretu."})
        
        totp = pyotp.TOTP(decrypted_totp_secret)
        token = request.POST.get("token")

        if totp.verify(token):
            # Kod poprawny, zaloguj użytkownika
            user_profile.reset_totp_attempts()
            user.backend = 'django.contrib.auth.backends.ModelBackend'
            login(request, user, backend=user.backend)
            return redirect('messages')
        else:
            user_profile.failed_totp_attempts += 1
            if user_profile.failed_totp_attempts >= 5:  # Limit prób
                user_profile.totp_lock_until = now() + timedelta(minutes=5)  
            user_profile.save()
            return render(request, 'verify_2fa.html', {'error': "Niepoprawny kod. Spróbuj ponownie."})

    return render(request, 'verify_2fa.html')

# Zmiana hasła
@login_required
def profile_view(request):
    if request.method == 'POST':
        user_profile = request.user.profile
        if not user_profile.rsa_public_key or not user_profile.rsa_private_key:
            user_profile.generate_rsa_keys()
            messages.success(request, 'Wygenerowano klucze RSA!')
        else:
            messages.error(request, 'Klucze RSA już istnieją.')
        return redirect('profile')

    return render(request, 'profile.html', {'user': request.user})

def change_password_view(request):
    if not request.user.is_authenticated:
        return redirect('login')

    if request.method == "POST":
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get("confirm_password")

        if new_password != confirm_password:
            return render(request, "change_password.html", {"errors": ["Hasła muszą być identyczne."]})

        # Walidacja hasła
        try:
            validate_password(new_password)
        except ValidationError as e:
            return render(request, 'change_password.html', {'errors': e.messages})

        # Tymczasowo zapisz nowe hasło w sesji
        request.session['new_password'] = new_password
        return redirect('verify_change_password')

    return render(request, 'change_password.html')

def verify_change_password_view(request):
    if not request.user.is_authenticated:
        return redirect('login')

    if request.method == "POST":
        user_profile = request.user.profile
        decrypted_totp_secret = user_profile.decrypt_totp_secret()
        if not decrypted_totp_secret:
            return render(request, 'verify_change_password.html', {'error': "Nie udało się odszyfrować sekretu."})

        totp = pyotp.TOTP(decrypted_totp_secret)
        token = request.POST.get('token')

        if totp.verify(token):
            # Zmień hasło
            new_password = request.session.get('new_password')
            if new_password:
                request.user.set_password(new_password)
                request.user.save()
                update_session_auth_hash(request, request.user)  # żeby nie wylogowało użytkownika 
                del request.session['new_password']  # Usuń hasło z sesji
                return redirect('messages')
        else:
            return render(request, 'verify_change_password.html', {'error': "Niepoprawny kod. Spróbuj ponownie."})

    return render(request, 'verify_change_password.html')

def reset_password_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")

        try:
            user = User.objects.get(username=username, email=email)
        except User.DoesNotExist:
            return render(request, 'reset_password.html', {"error": "Nieprawidłowe dane."})

        request.session['reset_user_id'] = user.id
        return redirect('verify_reset_password')

    return render(request, 'reset_password.html')

logger = logging.getLogger(__name__)

def verify_reset_password_view(request):
    user_id = request.session.get('reset_user_id')

    if not user_id:
        return redirect('reset_password')

    user = User.objects.get(id=user_id)

    if request.method == "POST":
        token = request.POST.get("token")
        user_profile = user.profile
        decrypted_totp_secret = user_profile.decrypt_totp_secret()
        if not decrypted_totp_secret:
            return render(request, 'verify_reset_password.html', {'error': "Nie udało się odszyfrować sekretu."})

        totp = pyotp.TOTP(decrypted_totp_secret) 

        if totp.verify(token):
            logger.info(f"Wysłałbym link ... na adres {user.email}")
            return redirect('login')
        else:
            return render(request, 'verify_reset_password.html', {"error": "Niepoprawny kod TOTP."})

    return render(request, 'verify_reset_password.html')
