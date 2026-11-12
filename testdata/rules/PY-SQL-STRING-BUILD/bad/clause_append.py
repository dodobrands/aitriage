def search(cursor, name):
    sql = "SELECT id FROM users"
    # ruleid: PY-SQL-STRING-BUILD
    sql += " WHERE name = '%s'" % name
    cursor.execute(sql)
