import yaml


def parse(path):
    with open(path) as fh:
        # ruleid: PY-YAML-LOAD
        return yaml.load(fh)
