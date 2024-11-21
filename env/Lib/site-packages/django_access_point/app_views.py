from django_access_point.models.custom_field import CUSTOM_FIELD_STATUS
from django_access_point.models.user import USER_TYPE_CHOICES, USER_STATUS_CHOICES
from django_access_point.views.custom_field import CustomFieldViewSet
from django_access_point.views.crud import CrudViewSet

from .models import User, UserCustomField, UserCustomFieldValue
from .serializers import UserSerializer, UserCustomFieldSerializer


class PlatformUser(CrudViewSet):
    queryset = User.objects.filter(user_type=USER_TYPE_CHOICES[0][0]).exclude(
        status=USER_STATUS_CHOICES[0][0]
    )
    list_fields = {"id": "ID", "name": "Name", "email": "Email Address"}
    serializer_class = UserSerializer
    custom_field_model = UserCustomField
    custom_field_value_model = UserCustomFieldValue

    # def get_list_fields(self):
    #     return {"id": "ID","name": "Name", "email": "Email Address" }


class PlatformUserCustomField(CustomFieldViewSet):
    queryset = UserCustomField.objects.filter(status=CUSTOM_FIELD_STATUS[1][0])
    serializer_class = UserCustomFieldSerializer
