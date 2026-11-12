import os

# ruleid: DJANGO-WILDCARD-HOSTS
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "*").split(",")
