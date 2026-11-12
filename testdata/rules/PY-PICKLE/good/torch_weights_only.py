import torch


def load_weights(path):
    return torch.load(path, weights_only=True)
