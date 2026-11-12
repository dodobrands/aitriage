import yaml


def parse(body):
    return yaml.load(body, Loader=yaml.SafeLoader)


def parse_c(body):
    return yaml.load(body, Loader=yaml.CSafeLoader)
