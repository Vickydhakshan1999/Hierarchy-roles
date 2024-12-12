# Generated by Django 4.2.17 on 2024-12-11 07:05

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('userApp', '0011_userdetails'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='tenant',
            name='slug',
        ),
        migrations.AddField(
            model_name='tenant',
            name='status',
            field=models.CharField(choices=[('deleted', 'Deleted'), ('active', 'Active'), ('inactive', 'Inactive')], default='active', max_length=50),
        ),
        migrations.AddField(
            model_name='usercustomfieldvalue',
            name='checkbox_field',
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='usercustomfieldvalue',
            name='date_field',
            field=models.DateField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='usercustomfieldvalue',
            name='dropdown_field',
            field=models.JSONField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='usercustomfieldvalue',
            name='file_field',
            field=models.FileField(blank=True, upload_to=''),
        ),
        migrations.AddField(
            model_name='usercustomfieldvalue',
            name='multiselect_checkbox_field',
            field=models.JSONField(default=None, null=True),
        ),
        migrations.AddField(
            model_name='usercustomfieldvalue',
            name='radio_field',
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name='usercustomfieldvalue',
            name='status',
            field=models.CharField(choices=[('deleted', 'Deleted'), ('active', 'Active')], default='active', max_length=20),
        ),
        migrations.AlterField(
            model_name='tenant',
            name='owner',
            field=models.ForeignKey(default=None, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='tenant_owner', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='user',
            name='status',
            field=models.CharField(choices=[('deleted', 'Deleted'), ('active', 'Active'), ('inactive', 'Inactive'), ('not_verified', 'Not Verified')], default='not_verified', max_length=50),
        ),
    ]
