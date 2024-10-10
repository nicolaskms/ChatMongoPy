class User:
    def __init__(self, nickname: str,
                 email: str,
                 password: str):
        self.nickname = nickname
        self.email = email
        self.password = password

    def __set_name__(self, nickname):
        self.nickname = nickname

class Message:
    def __init__(self, nickname_from: str,
                 nickname_to: str,
                 content: str):
        self.nickname_to = nickname_to
        self.content = content
        self.nickname_from = nickname_from
