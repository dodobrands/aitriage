import pandas as pd


def load(conn, table):
    # ruleid: FLASK-RAW-SQL
    return pd.read_sql(f"SELECT * FROM {table}", conn)
