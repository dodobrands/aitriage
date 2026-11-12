import yaml


def parse(body):
    # ruleid: PY-YAML-LOAD
    return yaml.load(body, Loader=yaml.Loader)
