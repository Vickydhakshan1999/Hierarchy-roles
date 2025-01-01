from django.contrib.auth.models import Group, Permission
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

class UserDetails(models.Model):
    # related_name = allows you to access the UserDetails instance from the User 
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="details")
    address = models.TextField()
    date_of_birth = models.DateField(null=True, blank=True)
    

    def __str__(self):  
        return f"Details of {self.user}"   
    

class RoleHierarchy(models.Model):
    parent_role = models.ForeignKey(Group, related_name='parent_roles', on_delete=models.CASCADE)
    child_role = models.ForeignKey(Group, related_name='child_roles', on_delete=models.CASCADE)
    # restricted_permissions = models.ManyToManyField(Permission, blank=True) 

    class Meta:
        unique_together = ('parent_role', 'child_role')  # Prevent duplicate mappings

    def __str__(self):
        return f'{self.child_role.name} inherits permissions from {self.parent_role.name}'
    

class LeaveForm(models.Model):
    # employee = models.ForeignKey(User, on_delete=models.CASCADE, related_name='leave_forms')
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name='leave_forms')
    start_date = models.DateField()
    end_date = models.DateField()
    reason = models.TextField()

    def __str__(self):
        return f"{self.employee.xname} - {self.start_date} to {self.end_date}"    



