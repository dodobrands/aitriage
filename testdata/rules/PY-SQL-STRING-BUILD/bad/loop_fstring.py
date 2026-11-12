def columns(cursor, catalogs):
    schema = {}
    for catalog in catalogs:
        # ruleid: PY-SQL-STRING-BUILD
        query = f"""
            SELECT table_schema, table_name
            FROM {catalog}.information_schema.columns
        """
        cursor.execute(query)
        schema[catalog] = cursor.fetchall()
    return schema
