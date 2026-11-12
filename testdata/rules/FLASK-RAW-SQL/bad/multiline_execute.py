def products(cursor, category):
    # ruleid: FLASK-RAW-SQL
    cursor.execute(
        "SELECT id, name FROM products WHERE category = '{}'".format(category)
    )
    return cursor.fetchall()
