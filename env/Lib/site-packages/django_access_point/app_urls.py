from django.urls import path
from rest_framework.routers import DefaultRouter

from .views import PlatformUser, PlatformUserCustomField

router = DefaultRouter()
router.register(r"custom-fields/platform/users",PlatformUserCustomField,basename="platform.user.custom_fields")
router.register(r"platform/users", PlatformUser, basename="platform.user")

urlpatterns = [
    # path('auth/login', "")
]

urlpatterns += router.urls
