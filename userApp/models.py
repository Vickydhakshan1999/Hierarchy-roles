from django.contrib.auth.models import Group
from django.db import models

from django_access_point.models.user import TenantBase, UserBase
from django_access_point.models.custom_field import CustomFieldBase, CustomFieldValueBase



class Tenant(TenantBase):
    name = models.CharField(max_length=100)
    description = models.TextField(max_length=200)


class User(UserBase):
    phone_no = models.CharField(max_length=100)

    groups = models.ManyToManyField(Group, related_name='user_groups', blank=True)

class UserCustomField(CustomFieldBase):
    tenant = models.ForeignKey(
        Tenant, on_delete=models.CASCADE, null=True, default=None
    )


class UserCustomFieldValue(CustomFieldValueBase):
    user_submission = models.ForeignKey(User, related_name="user_custom_field_values", on_delete=models.CASCADE)
    custom_field = models.ForeignKey(UserCustomField, on_delete=models.CASCADE)


