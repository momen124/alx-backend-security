# Generated by Django 5.1.4 on 2025-07-17 19:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ip_tracking', '0002_blockedip'),
    ]

    operations = [
        migrations.AddField(
            model_name='requestlog',
            name='city',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='requestlog',
            name='country',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
