def find(conn, user_id):
    cur = conn.cursor()
    # ruleid: FLASK-RAW-SQL
    cur.execute("SELECT * FROM users WHERE id = " + user_id)
    return cur.fetchall()
