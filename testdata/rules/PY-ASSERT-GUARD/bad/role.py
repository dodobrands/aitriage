def approve(user, item):
    # ruleid: PY-ASSERT-GUARD
    assert user.role == "approver"
    item.approve()
