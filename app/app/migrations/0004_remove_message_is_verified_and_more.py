# Generated by Django 4.2 on 2025-01-25 20:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0003_message_is_verified_userprofile_rsa_private_key_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='message',
            name='is_verified',
        ),
        migrations.RemoveField(
            model_name='userprofile',
            name='rsa_private_key',
        ),
        migrations.AddField(
            model_name='message',
            name='signature',
            field=models.TextField(blank=True, null=True),
        ),
    ]
