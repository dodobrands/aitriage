import yaml


def load_config(path):
    with open(path) as fh:
        return yaml.load(fh, Loader=yaml.SafeLoader)


def load_request(body):
    # ruleid: PY-YAML-LOAD
    return yaml.load(body, Loader=yaml.UnsafeLoader)
