import pickle
from flask import request


def load_cache(path):
    with open(path, "rb") as fh:
        return pickle.load(fh)
