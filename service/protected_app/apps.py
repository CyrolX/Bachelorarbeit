from django.apps import AppConfig


class ProtectedAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'protected_app'
