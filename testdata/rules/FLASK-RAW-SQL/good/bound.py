from sqlalchemy import text
from app import db


def find(name):
    return db.session.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name})


def find_cursor(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
