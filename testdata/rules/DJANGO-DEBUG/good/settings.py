import os

# Never ship DEBUG = True; enable it locally with DJANGO_DEBUG=1.
DEBUG = os.environ.get("DJANGO_DEBUG", "") == "1"
ALLOWED_HOSTS = ["app.example.com"]
