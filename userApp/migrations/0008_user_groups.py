# Generated by Django 5.1.3 on 2024-11-14 09:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
        ('userApp', '0007_delete_groups'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='groups',
            field=models.ManyToManyField(blank=True, related_name='user_groups', to='auth.group'),
        ),
    ]
