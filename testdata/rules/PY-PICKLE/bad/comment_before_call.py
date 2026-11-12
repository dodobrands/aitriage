import pickle

# Legacy note: we used to call pickle.loads() on cache entries.
def a():
    return 1


def restore(blob):
    # ruleid: PY-PICKLE
    return pickle.loads(blob)
