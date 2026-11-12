def check(user):
    """
    assert user.is_admin  -- do not do this, asserts are stripped with -O
    """
    if not user.is_admin:
        raise PermissionError()
