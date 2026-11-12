def search(cursor, name):
    """Do not write sql = "SELECT id FROM users WHERE name = '%s'" % name."""
    cursor.execute("SELECT id FROM users WHERE name = %s", (name,))
