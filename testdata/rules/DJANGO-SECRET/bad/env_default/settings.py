import os

# ruleid: DJANGO-SECRET
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "fallback-not-a-real-__JOIN__key-0123456789")
