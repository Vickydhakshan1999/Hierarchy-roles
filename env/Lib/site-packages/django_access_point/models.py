from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.exceptions import ImproperlyConfigured

USER_TYPE_CHOICES = [
    ('platform', 'Platform'),
    ('tenant', 'Tenant')
]

USER_STATUS_CHOICES = [
    ('deleted', 'Deleted'),
    ('active', 'Active'),
    ('inactive', 'Inactive'),
    ('not_verified', 'Not Verified'),
]

CUSTOM_FIELD_TYPES = []

class TenantBase(models.Model):
    """
    Contains global data for the tenant model.
    """
    slug = models.SlugField(max_length=200, blank=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="tenant_owner")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    def add_user(self, user_obj, is_superuser: bool = False):
        """
        Add user to tenant.
        """
        if self.user.filter(id=user_obj.pk).exists():
            raise ValueError(f"User already added to tenant: {user_obj}")

        user_obj.tenant = self
        user_obj.save()

    def remove_user(self, user_obj):
        """
        Remove user from tenant & soft delete user.
        """
        # Test that user is already in the tenant
        self.user.get(pk=user_obj.pk)

        # Don't allow removing an owner from a tenant.
        if user_obj.pk == self.owner.pk:
            raise ValueError(f"Cannot remove owner from tenant: {self.owner}")

        # Remove user from tenant
        user_obj.tenant = None
        user_obj.save()

class UserBase(AbstractBaseUser):
    """
    Base user model for multi-tenant system.
    """
    tenant_model = getattr(settings, 'TENANT_MODEL', None)

    if tenant_model is None:
        raise ImproperlyConfigured("Django Access Point: TENANT_MODEL must be set in the settings.")

    tenant = models.ForeignKey(settings.TENANT_MODEL, null=True, related_name="user", on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    email = models.EmailField(unique=True, db_index=True)
    user_type = models.CharField(
        max_length=50,
        choices=USER_TYPE_CHOICES,
        default=USER_TYPE_CHOICES[0][0],
    )
    status = models.CharField(
        max_length=50,
        choices=USER_STATUS_CHOICES,
        default=USER_STATUS_CHOICES[1][0],
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    objects = BaseUserManager()

    class Meta:
        abstract = True

    def is_user_active(self):
        return self.status == USER_STATUS_CHOICES[1][0]

    def is_platform_user(self):
        return self.user_type == USER_TYPE_CHOICES[0][0]

    def is_tenant_user(self):
        return self.user_type == USER_TYPE_CHOICES[1][0]

    """
    To use 'mobile number' or any other field for logging in as the username, you can extend the 'ModelBackend' 
    and add it to the AUTHENTICATION_BACKENDS in the settings:
        1. Extend ModelBackend: Create a custom authentication backend by extending Django’s ModelBackend.
        2. Add to AUTHENTICATION_BACKENDS: Include the custom backend in the AUTHENTICATION_BACKENDS list in 
        your settings.py file.
    """

class CustomFieldBase(models.Model):
    label = models.TextField(max_length=200)
    field_type = models.TextField(max_length=200)

    class Meta:
        abstract = True

class CustomFieldValueBase(models.Model):
    value = models.TextField(max_length=200)

    class Meta:
        abstract = True

"""
class CustomField(models.Model):
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey('content_type', 'object_id')

    label = models.TextField(max_length=200)
    field_type = models.TextField(max_length=200)


class CustomFieldValue(models.Model):
    content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    object_id = models.PositiveIntegerField()
    content_object = GenericForeignKey('content_type', 'object_id')

    custom_field = models.ForeignKey(CustomField, on_delete=models.CASCADE)
    value = models.TextField(max_length=200)
"""


"""
from django.contrib.contenttypes.models import ContentType
from myapp.models import CustomField, CustomFieldValue, MyModel  # Replace MyModel with your model

# Creating a custom field for MyModel
my_model_type = ContentType.objects.get_for_model(MyModel)
custom_field = CustomField.objects.create(
    content_type=my_model_type,
    object_id=my_model_instance.id,  # An instance of MyModel
    label="Custom Label",
    field_type="Text"
)

# Creating a custom field value for MyModel
custom_field_value = CustomFieldValue.objects.create(
    content_type=my_model_type,
    object_id=my_model_instance.id,
    custom_field=custom_field,
    value="Some value"
)
"""