from sqlalchemy import text
from app import db


def find(name):
    # ruleid: FLASK-RAW-SQL
    return db.session.execute(text(f'SELECT * FROM users WHERE name = \'{name}\''))
