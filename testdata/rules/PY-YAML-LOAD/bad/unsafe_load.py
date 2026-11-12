import yaml


def parse(body):
    # ruleid: PY-YAML-LOAD
    return yaml.unsafe_load(body)
