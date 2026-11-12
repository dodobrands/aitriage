import torch

def restore(path):
    # ruleid: LLM-UNSAFE-MODEL-LOAD
    return torch.load(path, map_location="cpu", weights_only=False)
