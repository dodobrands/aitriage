def build(items):
    assert len(items) > 0, "controller needs items"
    assert isinstance(items, list)  # role of this list: queue
    return items
