from django.db import models
from django.conf import settings
from django.contrib.auth.models import User
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from django.db.models.signals import post_save
from django.dispatch import receiver

class Message(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="messages")
    content = models.TextField() 
    created_at = models.DateTimeField(auto_now_add=True)
    is_verified = models.BooleanField(default=False)

    
    
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    totp_secret = models.CharField(max_length=32, blank=True, null=True)
    rsa_public_key = models.TextField(blank=True, null=True)  
    rsa_private_key = models.TextField(blank=True, null=True) 

    def generate_rsa_keys(self):
        key = RSA.generate(2048)
        self.rsa_private_key = key.export_key().decode('utf-8')
        self.rsa_public_key = key.publickey().export_key().decode('utf-8')
        self.save()

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()