from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from app.models import Message

@login_required
def messages_view(request):
    messages = Message.objects.all()
    return render(request, 'messages.html', {'messages': messages})

@login_required
def create_message_view(request):
    if request.method == "POST":
        content = request.POST.get("content")
        private_key = request.POST.get("private_key")
        message = Message.objects.create(user=request.user, content=content)
        message.sign_message(private_key)
        return redirect('messages')
    return render(request, 'create_message.html')
