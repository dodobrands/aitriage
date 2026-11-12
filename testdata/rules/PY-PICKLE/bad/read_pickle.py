import pandas as pd


def load_frame(path):
    # ruleid: PY-PICKLE
    return pd.read_pickle(path)
