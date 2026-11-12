import os

DEBUG = os.environ.get("DJANGO_DEBUG", "") == "1"
# ruleid: DJANGO-SECRET
SECRET_KEY = "django-insecure-not-a-real-__JOIN__key-0123456789abcdefghij"
