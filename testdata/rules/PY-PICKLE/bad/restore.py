import pickle


def restore(blob):
    # ruleid: PY-PICKLE
    return pickle.loads(blob)
