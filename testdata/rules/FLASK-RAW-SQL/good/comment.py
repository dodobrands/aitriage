def find(cursor, user_id):
    # Was: cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
