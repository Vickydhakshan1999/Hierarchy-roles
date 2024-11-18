from django_access_point.models.custom_field import CUSTOM_FIELD_STATUS
from django_access_point.models.user import USER_TYPE_CHOICES, USER_STATUS_CHOICES
from django_access_point.views.custom_field import CustomFieldViewSet
from django_access_point.views.crud import CrudViewSet
from django.contrib.auth import get_user_model


from django.contrib.auth.models import Group
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate

# from userApp.permissions import IsAdminUser

from .models import User, UserCustomField, UserCustomFieldValue
from .serializers import UserSerializer, UserCustomFieldSerializer
from rest_framework.permissions import IsAuthenticated
# from .permissions import IsAdmin, IsManager, IsAdminOrManager


from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from rest_framework.decorators import api_view, permission_classes

from django.contrib.auth.hashers import check_password


# @permission_classes([IsAuthenticated, IsAdminUser])
class PlatformUser(CrudViewSet):
    queryset = User.objects.filter(user_type=USER_TYPE_CHOICES[0][0]).exclude(
        status=USER_STATUS_CHOICES[0][0]
    )
    serializer_class = UserSerializer
    custom_field_model = UserCustomField
    custom_field_value_model = UserCustomFieldValue


    def create(self, request, *args, **kwargs):
        # Initialize the serializer with the request data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        print(f"Request data: {request.data}") 

        # Save the user without groups initially
        user = serializer.save()

        user.password = request.data.get("password")

        # Get the group ID from the request data
        group_id = request.data.get("group", None)  # Fetch the group ID from request data
        print(f"Group ID from request: {group_id}")  # Debugging line
        

        if group_id:
            # Ensure the group exists and assign it to the user
            try:
                group = Group.objects.get(id=group_id)
                user.groups.clear()  # Clear any existing groups to ensure only the selected group is assigned
                user.groups.add(group)  # Add the group to the user
                user.save()  # Save the user with the assigned group
                print(f"Group '{group.name}' assigned to user '{user.name}'.")  # Debugging line
            except Group.DoesNotExist:
                raise NotFound(detail="Group with the given ID does not exist.")
        
        # Return the response with the saved user data
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    


# Login api
@api_view(['POST'])
def login_view(request):
    # Get the email and password from the request
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({'error': 'Email and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        # Fetch the user by email
        User = get_user_model()
        user = User.objects.get(email=email)

        # Compare plain-text password directly
        if user.password == password:
            # Check user group only after password validation
            if user.groups.filter(name='Manager').exists():
                return Response({'Restricted': 'Managers are not allowed to log in.'}, status=status.HTTP_403_FORBIDDEN)
            elif user.groups.filter(name='Admin').exists():
                return Response({
                    'message': 'Login successful',
                    'user_id': user.id,
                    'username': user.name,
                    'role': 'Admin',
                    'access': 'View only'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'message': 'Login successful',
                    'user_id': user.id,
                    'username': user.name,
                    'role': 'Other',
                }, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid password'}, status=status.HTTP_400_BAD_REQUEST)
    except User.DoesNotExist:
        return Response({'error': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
    

class PlatformUserCustomField(CustomFieldViewSet):
    queryset = UserCustomField.objects.filter(status=CUSTOM_FIELD_STATUS[1][0])
    serializer_class = UserCustomFieldSerializer


# ....................

# Create a new group
@api_view(['POST'])

def create_group(request):
    """
    This view allows the creation of a new group.
    """
    group_name = request.data.get('name', None)
    if not group_name:
        return Response({'detail': 'Group name is required.'}, status=status.HTTP_400_BAD_REQUEST)

    # Create the group
    group = Group.objects.create(name=group_name)
    
    return Response({'detail': f'Group "{group_name}" created successfully.'}, status=status.HTTP_201_CREATED)


# List all groups
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_groups(request):
    """
    This view returns a list of all groups.
    """
    groups = Group.objects.all()
    group_names = [group.name for group in groups]
    return Response({'groups': group_names}, status=status.HTTP_200_OK)


# Retrieve a specific group by its ID
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def retrieve_group(request, group_id):
    """
    This view returns details of a single group.
    """
    try:
        group = Group.objects.get(id=group_id)
    except Group.DoesNotExist:
        raise NotFound(detail="Group not found")

    return Response({'id': group.id, 'name': group.name}, status=status.HTTP_200_OK)


# Update a group
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_group(request, group_id):
    """
    This view updates the name of an existing group.
    """
    try:
        group = Group.objects.get(id=group_id)
    except Group.DoesNotExist:
        raise NotFound(detail="Group not found")
    
    new_name = request.data.get('name', None)
    if not new_name:
        return Response({'detail': 'New group name is required.'}, status=status.HTTP_400_BAD_REQUEST)
    
    group.name = new_name
    group.save()

    return Response({'detail': f'Group name updated to "{new_name}".'}, status=status.HTTP_200_OK)


# Delete a group
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_group(request, group_id):
    """
    This view deletes a group.
    """
    try:
        group = Group.objects.get(id=group_id)
    except Group.DoesNotExist:
        raise NotFound(detail="Group not found")
    
    group.delete()

    return Response({'detail': 'Group deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)


# ..................................

# Create a new permission (only for authenticated users)
@api_view(['POST'])
# @permission_classes([IsAuthenticated])
def create_permission(request):
    name = request.data.get('name')
    codename = request.data.get('codename')
    app_label = request.data.get('app_label')
    model_name = request.data.get('model_name')
    
    if not all([name, codename, model_name]):
        return Response(
            {'detail': 'Name, codename, and model_name are required.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        content_type = ContentType.objects.get(app_label=app_label, model=model_name)
        permission = Permission.objects.create(
            name=name,
            codename=codename,
            content_type=content_type
        )
        return Response(
            {'detail': f'Permission "{name}" created successfully.'},
            status=status.HTTP_201_CREATED 
        )
    except ContentType.DoesNotExist:
        return Response(
            {'detail': f'Model "{model_name}" does not exist.'},
            status=status.HTTP_400_BAD_REQUEST
        )


# List all permissions (only for authenticated users)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_permissions(request):
    permissions = Permission.objects.all().values('id', 'name', 'codename', 'content_type__model')
    return Response({'permissions': list(permissions)}, status=status.HTTP_200_OK)


# Retrieve a specific permission by ID (only for authenticated users)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def retrieve_permission(request, permission_id):
    try:
        permission = Permission.objects.get(id=permission_id)
        return Response({
            'id': permission.id,
            'name': permission.name,
            'codename': permission.codename,
            'model': permission.content_type.model
        }, status=status.HTTP_200_OK)
    except Permission.DoesNotExist:
        raise NotFound(detail="Permission not found")


# Update a permission by ID (only for authenticated users)
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def update_permission(request, permission_id):
    try:
        permission = Permission.objects.get(id=permission_id)
    except Permission.DoesNotExist:
        raise NotFound(detail="Permission not found")
    
    name = request.data.get('name')
    codename = request.data.get('codename')
    
    if name:
        permission.name = name
    if codename:
        permission.codename = codename
    
    permission.save()
    return Response({'detail': 'Permission updated successfully.'}, status=status.HTTP_200_OK)


# Delete a permission by ID (only for authenticated users)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_permission(request, permission_id):
    try:
        permission = Permission.objects.get(id=permission_id)
        permission.delete()
        return Response({'detail': 'Permission deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)
    except Permission.DoesNotExist:
        raise NotFound(detail="Permission not found")


# ..............
# maping permission to group
@api_view(['POST'])
def assign_permission_to_group(request):
    group_name = request.data.get('group_name')
    permission_codename = request.data.get('permission_codename')
    
    if not all([group_name, permission_codename]):
        return Response(
            {'detail': 'Group name and permission codename are required.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    try:
        # Get the group by name
        group = Group.objects.get(name=group_name)
        
        # Get the permission by codename
        permission = Permission.objects.get(codename=permission_codename)
        
        # Add permission to the group
        group.permissions.add(permission)
        
        return Response(
            {'detail': f'Permission "{permission_codename}" added to group "{group_name}" successfully.'},
            status=status.HTTP_200_OK
        )
    except Group.DoesNotExist:
        return Response(
            {'detail': f'Group "{group_name}" does not exist.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Permission.DoesNotExist:
        return Response(
            {'detail': f'Permission with codename "{permission_codename}" does not exist.'},
            status=status.HTTP_400_BAD_REQUEST
        )

# .........
# mapping user to group
@api_view(['POST'])
# @permission_classes([IsAuthenticated])  # Ensure only authenticated users can use this
def assign_user_to_group(request):
    user_id = request.data.get('user_id')  # User ID to map
    group_name = request.data.get('group_name')  # Group to assign the user to
    
    if not all([user_id, group_name]):
        return Response({'detail': 'user_id and group_name are required.'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(id=user_id)  # Get the user by ID
        group = Group.objects.get(name=group_name)  # Get the group by name

        # Add the user to the group
        user.groups.add(group)
        return Response({'detail': f'User "{user.phone_no}" assigned to group "{group_name}" successfully.'}, 
                        status=status.HTTP_200_OK)
    
    except User.DoesNotExist:
        return Response({'detail': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
    
    except Group.DoesNotExist:
        return Response({'detail': 'Group not found.'}, status=status.HTTP_404_NOT_FOUND)







    