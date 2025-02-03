from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from django.db.models.signals import post_save
from django.dispatch import receiver
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import base64
import os
from django.utils.timezone import now, timedelta

class Message(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="messages")
    content = models.TextField() 
    created_at = models.DateTimeField(auto_now_add=True)
    signature = models.TextField(blank=True, null=True)
    
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    totp_secret = models.CharField(max_length=255, blank=True, null=True)
    failed_totp_attempts = models.IntegerField(default=0) 
    totp_lock_until = models.DateTimeField(null=True, blank=True)
    rsa_public_key = models.TextField(blank=True, null=True)

    def is_totp_locked(self):
        if self.totp_lock_until and self.totp_lock_until > now():
            return True
        return False

    def reset_totp_attempts(self):
        self.failed_totp_attempts = 0
        self.totp_lock_until = None
        self.save()

    @staticmethod
    def get_encryption_key():
        from django.conf import settings
        return bytes.fromhex(settings.TOTP_ENCRYPTION_KEY)

    def encrypt_totp_secret(self, totp_secret):
        cipher = AES.new(self.get_encryption_key(), AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(totp_secret.encode('utf-8'), AES.block_size))
        return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')  # Łączymy IV z szyfrowanym tekstem

    def decrypt_totp_secret(self):
        try:
            encrypted_data = base64.b64decode(self.totp_secret.encode('utf-8'))
            iv = encrypted_data[:AES.block_size]  # Wyciągamy IV
            ciphertext = encrypted_data[AES.block_size:]
            cipher = AES.new(self.get_encryption_key(), AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
        except Exception:
            return None   

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()