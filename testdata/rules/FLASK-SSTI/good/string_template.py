from string import Template


def greeting(text, name):
    return Template(text).safe_substitute(name=name)
