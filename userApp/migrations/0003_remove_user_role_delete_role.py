# Generated by Django 5.1.3 on 2024-11-13 12:08

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('userApp', '0002_role_user_role'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='role',
        ),
        migrations.DeleteModel(
            name='Role',
        ),
    ]