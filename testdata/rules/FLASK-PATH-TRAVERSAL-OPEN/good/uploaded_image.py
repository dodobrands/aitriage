from flask import request
from PIL import Image


def thumbnail():
    img = Image.open(request.files["image"])
    img.thumbnail((128, 128))
    return img
