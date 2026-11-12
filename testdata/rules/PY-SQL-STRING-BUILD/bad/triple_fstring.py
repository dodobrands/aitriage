def orders(cursor, user_id):
    # ruleid: PY-SQL-STRING-BUILD
    sql = f"""
        SELECT id, total
        FROM orders
        WHERE user_id = {user_id}
    """
    cursor.execute(sql)
    return cursor.fetchall()
