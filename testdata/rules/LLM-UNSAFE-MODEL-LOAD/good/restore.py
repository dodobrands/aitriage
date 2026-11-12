import torch
from safetensors.torch import load_file

def restore(path):
    state = torch.load(path, map_location="cpu", weights_only=True)
    return state, load_file("model.safetensors")
