def refresh(cache):
    try:
        cache.refresh()
    # ruleid: FAST-LAZY-EXC
    except:
        pass
