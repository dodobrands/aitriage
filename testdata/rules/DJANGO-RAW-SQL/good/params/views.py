from django.db import connection


def applied_coupon(request):
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT coupon_code FROM applied_coupon WHERE coupon_code = %s",
            [request.POST["coupon_code"]],
        )
        cursor.execute("SELECT pg_try_advisory_xact_lock(%s, %s)", (1, 2))
        cursor.execute("SELECT * FROM coupon WHERE id = %(id)s", {"id": 1})
        # cursor.execute("SELECT * FROM coupon WHERE code = '" + code + "'")
        return cursor.fetchall()
