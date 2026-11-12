def delete_user(current_user, user_id):
    if not current_user.is_admin:
        raise PermissionError("admin only")
    remove(user_id)
