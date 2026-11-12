import yaml


def parse(body):
    """Never call yaml.load(body) on request data; use safe_load."""
    return yaml.safe_load(body)
