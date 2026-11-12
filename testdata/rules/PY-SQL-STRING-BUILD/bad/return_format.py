def delete_query(table, item_id):
    # ruleid: PY-SQL-STRING-BUILD
    return "DELETE FROM {} WHERE id = {}".format(table, item_id)
