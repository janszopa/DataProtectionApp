from django.db import models
from django.conf import settings
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256

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
