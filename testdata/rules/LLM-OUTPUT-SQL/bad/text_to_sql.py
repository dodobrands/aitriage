def answer(cursor, llm_output):
    # ruleid: LLM-OUTPUT-SQL
    cursor.execute(f"SELECT * FROM orders WHERE {llm_output}")
    return cursor.fetchall()
