import ast


def check(src):
    return ast.parse(src, mode="eval")
