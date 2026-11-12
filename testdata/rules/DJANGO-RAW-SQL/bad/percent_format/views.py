from django.db import connection


def orders(request):
    status = request.GET["status"]
    with connection.cursor() as cursor:
        # ruleid: DJANGO-RAW-SQL
        cursor.execute("SELECT id FROM shop_order WHERE status = '%s'" % status)
        return cursor.fetchall()
