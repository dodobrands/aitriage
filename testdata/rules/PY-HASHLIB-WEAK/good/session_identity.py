import hashlib


class User:
    def get_id(self):
        identity = hashlib.md5(
            "{},{}".format(self.email, self.password_hash).encode(), usedforsecurity=False
        ).hexdigest()
        return "{0}-{1}".format(self.id, identity)
