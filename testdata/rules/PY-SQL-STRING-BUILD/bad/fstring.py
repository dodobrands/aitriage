def search(conn, name):
    # ruleid: PY-SQL-STRING-BUILD
    sql = f"SELECT id FROM users WHERE name = '{name}'"
    return conn.execute(sql)
