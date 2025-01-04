from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
import pyotp
from django.contrib.auth.decorators import login_required

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
        if 'step' not in request.session:
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
                request.session['step'] = 2  # Przejdź do konfiguracji 2FA
                return redirect('register')
            except ValidationError as e:
                return render(request, 'register.html', {'errors': e.messages})

             # Etap 2: Konfiguracja 2FA
        if request.session['step'] == 2:
            user_id = request.session['user_id']
            user = User.objects.get(id=user_id)
            user_profile = user.profile

            # Generowanie sekretu TOTP
            if not user_profile.totp_secret:
                user_profile.totp_secret = pyotp.random_base32()
                user_profile.save()

            totp = pyotp.TOTP(user_profile.totp_secret)
            qr_url = totp.provisioning_uri(user.username, issuer_name="Twoja Aplikacja")
            return render(request, 'setup_2fa.html', {'qr_url': qr_url})
        
    return render(request, 'register.html')

def logout_view(request):
    logout(request)
    return redirect('login')

# @login_required
# def enable_2fa(request):
#     user_profile = request.user.profile

#     # Generuj sekret TOTP, jeśli jeszcze go nie ma
#     if not user_profile.totp_secret:
#         user_profile.totp_secret = pyotp.random_base32()
#         user_profile.save()

#     # Wygeneruj URL do skanowania QR w Google Authenticator
#     totp = pyotp.TOTP(user_profile.totp_secret)
#     qr_url = totp.provisioning_uri(request.user.username, issuer_name="Twoja Aplikacja")

#     return render(request, 'enable_2fa.html', {'qr_url': qr_url})

def verify_2fa_view(request):
    if request.method == "POST":
        user_id = request.session.get('user_id')
        user = User.objects.get(id=user_id)
        totp = pyotp.TOTP(user.profile.totp_secret)
        token = request.POST.get("token")

        if totp.verify(token):
            # Kod poprawny, zaloguj użytkownika
            login(request, user)
            return redirect('dashboard')
        else:
            return render(request, 'verify_2fa.html', {'error': "Niepoprawny kod. Spróbuj ponownie."})

    return render(request, 'verify_2fa.html')