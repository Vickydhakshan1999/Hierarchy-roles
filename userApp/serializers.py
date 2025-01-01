from django_access_point.serializers.crud import CrudSerializer
from django_access_point.serializers.custom_field import CustomFieldSerializer

from django.contrib.auth.models import Group
from rest_framework import serializers
from .models import LeaveForm, User

from .models import User, UserCustomField
from .models import RoleHierarchy


class UserCustomFieldSerializer(CustomFieldSerializer):
    class Meta:
        model = UserCustomField
        fields = CustomFieldSerializer.Meta.fields


class UserSerializer(CrudSerializer):
    # groups = serializers.PrimaryKeyRelatedField(queryset=Group.objects.all(), many=True)
      
    #   group = serializers.PrimaryKeyRelatedField(queryset=Group.objects.all(), required=False)
 class Meta:
        model = User
        fields = ["name", "email", "phone_no", "password"]
        

from rest_framework import serializers
from .models import UserDetails

class UserDetailsSerializer(serializers.ModelSerializer):

    
    class Meta:
        model = UserDetails
        fields = ['user_id', 'address', 'date_of_birth']  


class RoleHierarchySerializer(serializers.ModelSerializer):

    parent_role = serializers.CharField(source='parent_role.name')  # Get the parent role name
    child_role = serializers.CharField(source='child_role.name')  # Get the child role name
    class Meta:
        model = RoleHierarchy
        fields = ['parent_role', 'child_role' ]  


class LeaveFormSerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(write_only=True)  # Receive user_id
    user_name = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model = LeaveForm
        fields = ['id', 'user_id', 'user_name', 'start_date', 'end_date', 'reason']

    def create(self, validated_data):
        # Retrieve the user using user_id
        user_id = validated_data.pop('user_id')
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise serializers.ValidationError({"user_id": "User does not exist."})
        
        validated_data['user'] = user  # Add the user instance to validated_data
        return super().create(validated_data)
             
