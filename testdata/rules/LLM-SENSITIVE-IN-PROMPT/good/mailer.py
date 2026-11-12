def reset_email(user, new_password):
    content = f"Hello {user.name}, your new password is {new_password}"
    return send(user.email, content)
