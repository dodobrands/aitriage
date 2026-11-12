class Template:
    def compile(self, source, mode="exec"):
        return self.parser.parse(source)
