def find(cursor, name):
    # ruleid: FLASK-RAW-SQL
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
