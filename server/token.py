

token_list = {}

MAX_CLIENT = 65535

def add_key(key):
    for i in xrange(0,MAX_CLIENT):
        if not token_list.has_key(str(i)):
            token_list[str(i)] = key
            return str(i)

    return None

def get_key(token):
    return token_list[token]

def del_token(token):
    token_list.pop(token)