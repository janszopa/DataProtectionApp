from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('messages')
    return render(request, 'login.html', {'errors': ["Nieprawidłowa nazwa uytkownika lub hasło."]})

def register_view(request):
    if request.method == "POST":
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
            return redirect('login')
        except ValidationError as e:
            return render(request, 'register.html', {'errors': e.messages})
        
    return render(request, 'register.html')

def logout_view(request):
    logout(request)
    return redirect('login')

