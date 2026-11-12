import ast


def parse(value):
    return ast.literal_eval(value)
