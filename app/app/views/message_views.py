from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from app.models import Message
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15

@login_required
def messages_view(request):
    messages = Message.objects.all()
    return render(request, 'messages.html', {'messages': messages})

@login_required
def create_message_view(request):
    if request.method == "POST":
        content = request.POST.get("content")
        private_key = request.POST.get("private_key")
        public_key = request.POST.get("public_key")

        # Walidacja danych wejściowych
        if not content or not private_key:
            return render(request, 'create_message.html', {"error": "Treść wiadomości i klucz prywatny są wymagane."})

        try:
            # Import klucza prywatnego
            private_key_obj = RSA.import_key(private_key)

            # Hashowanie zawartości wiadomości
            hash_obj = SHA256.new(content.encode('utf-8'))

            # Generowanie podpisu
            signature = pkcs1_15.new(private_key_obj).sign(hash_obj).hex()

            # Sprawdzenie, czy użytkownik ma już klucz publiczny w bazie
            user_profile = request.user.profile
            if not user_profile.rsa_public_key:
                user_profile.rsa_public_key = public_key
                user_profile.save()

            # Zapisanie wiadomości z podpisem
            Message.objects.create(
                user=request.user,
                content=content,
                signature=signature
            )

            return redirect('messages')
        except Exception as e:
            return render(request, 'create_message.html', {"error": f"Błąd: {str(e)}"})

    return render(request, 'create_message.html')

@login_required
def verify_message_view(request, message_id):
    try:
        message = Message.objects.get(id=message_id)
    except Message.DoesNotExist:
        return render(request, 'verify_message.html', {"error": "Nie znaleziono wiadomości."})

    user_profile = message.user.profile

    # Sprawdź, czy użytkownik ma klucz publiczny
    if not user_profile.rsa_public_key:
        return render(request, 'verify_message.html', {"error": "Brak klucza publicznego dla tego użytkownika, nie można potwierdzić tożsamości."})

    try:
        # Import klucza publicznego
        public_key = RSA.import_key(user_profile.rsa_public_key)

        # Hashowanie zawartości wiadomości
        hash_obj = SHA256.new(message.content.encode('utf-8'))

        # Weryfikacja podpisu
        pkcs1_15.new(public_key).verify(hash_obj, bytes.fromhex(message.signature))
        is_verified = True
    except (ValueError, TypeError):
        is_verified = False

    return render(request, 'verify_message.html', {"message": message, "is_verified": is_verified})
