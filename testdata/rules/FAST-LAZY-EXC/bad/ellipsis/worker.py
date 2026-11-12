def refresh(cache):
    try:
        cache.refresh()
    # ruleid: FAST-LAZY-EXC
    except Exception as exc:  # noqa: BLE001
        ...
