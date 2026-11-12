from django.db import connection


def applied_coupon(request):
    code = request.POST["coupon_code"]
    with connection.cursor() as cursor:
        # ruleid: DJANGO-RAW-SQL
        cursor.execute(
            "SELECT coupon_code FROM applied_coupon WHERE coupon_code = '"
            + code
            + "'"
        )
        return cursor.fetchall()
