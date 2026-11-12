import torch


def load_model(path):
    # ruleid: PY-PICKLE
    return torch.load(path, weights_only=False)
