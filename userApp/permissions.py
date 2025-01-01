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



from rest_framework.permissions import BasePermission
from .models import RoleHierarchy
from django.contrib.auth.models import Group

class RoleBasedAccessPermission(BasePermission):
    """
    Custom permission to enforce role-based access for leave forms.
    """

    def has_permission(self, request, view):
        # Ensure user is authenticated
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        user_groups = request.user.groups.all()
        if not user_groups:
            self.message = "You do not belong to any group."
            return False

        # Admin users can access all leave forms
        if RoleHierarchy.objects.filter(parent_role__name="admin", child_role__in=user_groups).exists():
            return True

        # Managers can only view leave forms of their subordinates
        for group in user_groups:
            role_hierarchy = RoleHierarchy.objects.filter(parent_role=group, child_role=obj.user.groups.first())
            if role_hierarchy.exists():
                return True

        # Employees can only view their own leave forms
        if obj.user == request.user:
            return True

        self.message = "You do not have permission to access this leave form."
        return False

  
