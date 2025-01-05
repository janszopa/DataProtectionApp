from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from django.db.models.signals import post_save
from django.dispatch import receiver

class Message(models.Model):
    # Powiązanie z użytkownikiem korzystającym z wbudowanego modelu auth_user
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="messages")
    content = models.TextField() 
    #signature = models.TextField(blank=True, null=True) 
    created_at = models.DateTimeField(auto_now_add=True)

    # def sign_message(self, private_key):
    #     """
    #     Tworzenie podpisu cyfrowego wiadomości przy użyciu klucza prywatnego.
    #     """
    #     key = RSA.import_key(private_key)
    #     h = SHA256.new(self.content.encode('utf-8'))
    #     self.signature = pkcs1_15.new(key).sign(h).hex()

    # def verify_signature(self, public_key):
    #     """
    #     Weryfikacja podpisu cyfrowego przy użyciu klucza publicznego.
    #     """
    #     key = RSA.import_key(public_key)
    #     h = SHA256.new(self.content.encode('utf-8'))
    #     try:
    #         pkcs1_15.new(key).verify(h, bytes.fromhex(self.signature))
    #         return True
    #     except (ValueError, TypeError):
    #         return False
    
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    totp_secret = models.CharField(max_length=32, blank=True, null=True)

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()