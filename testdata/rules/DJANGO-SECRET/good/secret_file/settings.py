from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

SECRET_KEY = Path("/run/secrets/django_secret_key").read_text().strip()
if not SECRET_KEY:
    raise ImproperlyConfigured("SECRET_KEY is empty")
