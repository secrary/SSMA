from src.check_strings import *


class get_strings:
    def __init__(self, filename):
        self.chars = b"A-Za-z0-9!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ "
        self.shortest_run = 4
        self.filename = filename
        self.regexp = b'[%s]{%d,}' % (self.chars, self.shortest_run)
        self.pattern = re.compile(self.regexp)

        with open(self.filename, 'rb') as f:
            list_bytes = self.process(f)
            strings = []
            for n in list_bytes:
                strings.append(n.decode())
        self.result = (is_website(strings), is_ip(strings), is_email(strings))

    def process(self, filename):
        data = filename.read()
        return self.pattern.findall(data)

    def get_result(self) -> tuple:
        return self.result

