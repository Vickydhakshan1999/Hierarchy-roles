# Generated by Django 4.2.17 on 2024-12-30 12:44

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('userApp', '0014_leaveform'),
    ]

    operations = [
        migrations.RenameField(
            model_name='leaveform',
            old_name='employee',
            new_name='user',
        ),
    ]
