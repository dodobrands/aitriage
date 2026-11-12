def download(full_path, model_path):
    weights = open(model_path, "rb").read()
    return FileResponse(open(full_path, "rb")), weights
