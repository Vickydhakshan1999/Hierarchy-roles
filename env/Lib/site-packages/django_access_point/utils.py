# from django.conf import settings
#
# try:
#     from django.apps import apps
#     get_model = apps.get_model
# except ImportError:
#     from django.db.models.loading import get_model
#
# def get_tenant_model():
#     return get_model(settings.TENANT_MODEL)