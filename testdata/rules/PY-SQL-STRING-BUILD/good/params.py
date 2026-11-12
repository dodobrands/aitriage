def search(cursor, name):
    sql = "SELECT id FROM users WHERE name = %s"
    cursor.execute(sql, (name,))
