from rest_framework.permissions import BasePermission
from django.contrib.auth.models import Permission


class CanCreateUserPermission(BasePermission):
    """
    Custom permission to check if the user has permission to create users.
    """

    def has_permission(self, request, view):
        user = request.user
        permission_code = 'add_user_create'  
        permission = Permission.objects.filter(codename=permission_code).first()

        if not permission:
            return False

        
        return any(group.permissions.filter(id=permission.id).exists() for group in user.groups.all())


class CanDeleteUserPermission(BasePermission):
    """
    Custom permission to check if the user has permission to delete users.
    """

    def has_permission(self, request, view):
        user = request.user
        permission_code = 'add_user_delete'  
        permission = Permission.objects.filter(codename=permission_code).first()
    
        if not permission:
            return False
        
        
        return any(group.permissions.filter(id=permission.id).exists() for group in user.groups.all())
        # return("no permission")

class CanEditUserPermission(BasePermission):
    """
    Custom permission to check if the user has permission to edit users.
    """

    def has_permission(self, request, view):
        user = request.user
        permission_code = 'add_user_edit'  
        permission = Permission.objects.filter(codename=permission_code).first()

        if not permission:
            return False

        
        return any(group.permissions.filter(id=permission.id).exists() for group in user.groups.all())


class CanViewUserPermission(BasePermission):
    """
    Custom permission to check if the user has permission to view users.
    """

    def has_permission(self, request, view):
        user = request.user
        permission_code = 'add_user_view'  
        permission = Permission.objects.filter(codename=permission_code).first()

        if not permission:
            return False

        
        return any(group.permissions.filter(id=permission.id).exists() for group in user.groups.all())
