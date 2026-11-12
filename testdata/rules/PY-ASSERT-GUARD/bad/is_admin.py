def delete_user(current_user, user_id):
    # ruleid: PY-ASSERT-GUARD
    assert current_user.is_admin, "admin only"
    remove(user_id)
