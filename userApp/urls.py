from django.urls import path
from rest_framework.routers import DefaultRouter
from .views import create_group, list_groups, login_view, retrieve_group, update_group, delete_group
from .views import PlatformUser, PlatformUserCustomField
from . import views

router = DefaultRouter()
router.register(r"custom-fields/platform/users",PlatformUserCustomField,basename="platform.user.custom_fields")
router.register(r"platform/users", PlatformUser, basename="platform.user")


urlpatterns = [
    # path('auth/login', "")
    path('groups/', list_groups, name='list_groups'),
    path('groups/create/', create_group, name='create_group'),
    path('groups/<int:group_id>/', retrieve_group, name='retrieve_group'),
    path('groups/<int:group_id>/update/', update_group, name='update_group'),
    path('groups/<int:group_id>/delete/', delete_group, name='delete_group'),

    path('permissions/create/', views.create_permission, name='create_permission'),
    path('permissions/', views.list_permissions, name='list_permissions'),
    path('permissions/<int:permission_id>/', views.retrieve_permission, name='retrieve_permission'),
    path('permissions/update/<int:permission_id>/', views.update_permission, name='update_permission'),
    path('permissions/delete/<int:permission_id>/', views.delete_permission, name='delete_permission'),

    path('permissions/assign/', views.assign_permission_to_group, name='assign_permission_to_group'),

    path('users/assign_group/', views.assign_user_to_group, name='assign_user_to_group'),

    path('platform/login/', login_view, name='login'),

]

urlpatterns += router.urls
