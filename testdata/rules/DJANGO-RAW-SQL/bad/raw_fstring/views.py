from django.contrib.auth.models import User


def find_user(request):
    name = request.GET["name"]
    # ruleid: DJANGO-RAW-SQL
    return list(User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{name}'"))
