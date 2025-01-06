from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
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
from io import BytesIO


# Logowanie i rejestracja użytkownika
def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user:
            # Przechowaj ID użytkownika w sesji i przejdź do 2FA
            request.session['user_id'] = user.id
            return redirect('verify_2fa')
        else:
            return render(request, 'login.html', {'error': "Nieprawidłowe dane logowania."})

    return render(request, 'login.html')

def register_view(request):
    if request.method == "POST":
        # if 'step' not in request.session:
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
            #backend = get_backends()[0]  # Wybierz pierwszy backend
            #login(request, user, backend=backend.__class__.__name__)
            return redirect('setup_2fa')
        except ValidationError as e:
            return render(request, 'register.html', {'errors': e.messages})
    
    return render(request, 'register.html')

def logout_view(request):
    logout(request)
    return redirect('login')

# Dwuetapowa weryfikacja
def setup_2fa_view(request):
    #user_profile = request.user.profile
    user_id = request.session.get('user_id')
    user = User.objects.get(id=user_id)
    user_profile = user.profile
    # Generowanie sekretu TOTP
    if not user_profile.totp_secret:
        user_profile.totp_secret = pyotp.random_base32()
        user_profile.save()

    # Generowanie kodu QR
    totp = pyotp.TOTP(user_profile.totp_secret)
    qr_url = totp.provisioning_uri(request.user.username, issuer_name="Custom Twitter")

    qr = qrcode.make(qr_url)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()

    return render(request, 'setup_2fa.html', {'qr_base64': qr_base64})

def verify_2fa_view(request):
    if request.method == "POST":
        user_id = request.session.get('user_id')
        user = User.objects.get(id=user_id)
        totp = pyotp.TOTP(user.profile.totp_secret)
        token = request.POST.get("token")

        if totp.verify(token):
            # Kod poprawny, zaloguj użytkownika
            user.backend = 'django.contrib.auth.backends.ModelBackend'
            login(request, user, backend=user.backend)
            return redirect('messages')
        else:
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
        totp = pyotp.TOTP(request.user.profile.totp_secret)
        token = request.POST.get('token')

        if totp.verify(token):
            # Zmień hasło
            new_password = request.session.get('new_password')
            if new_password:
                request.user.set_password(new_password)
                request.user.save()
                del request.session['new_password']  # Usuń hasło z sesji
                return redirect('messages')
        else:
            return render(request, 'verify_change_password.html', {'error': "Niepoprawny kod. Spróbuj ponownie."})

    return render(request, 'verify_change_password.html')
