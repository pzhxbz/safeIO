
class Token:
    token_list = {}
    def __init__(self):
        pass

MAX_CLIENT = 65535

def add_key(key):
    for i in xrange(0,MAX_CLIENT):
        if not Token.token_list.has_key(str(i)):
            Token.token_list[str(i)] = key
            return i

    return None

def get_key(token):
    try:
        return Token.token_list[token]
    except Exception:
        return None

   

def del_token(token):
    try:
        Token.token_list.pop(token)
    except Exception:
        return