import pickle


def save(obj, path):
    with open(path, "wb") as fh:
        pickle.dump(obj, fh)
    return pickle.dumps(obj)
