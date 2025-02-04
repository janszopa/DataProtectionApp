# Generated by Django 4.2 on 2025-01-28 15:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0005_alter_userprofile_totp_secret'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='failed_totp_attempts',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='userprofile',
            name='totp_lock_until',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
