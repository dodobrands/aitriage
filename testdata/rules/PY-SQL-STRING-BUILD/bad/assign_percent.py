def search(db, term):
    # ruleid: PY-SQL-STRING-BUILD
    query = "SELECT * FROM items WHERE name LIKE '%%%s%%'" % term
    return db.session.execute(query)
