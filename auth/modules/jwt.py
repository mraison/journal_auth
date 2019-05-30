import hashlib
import hmac
import json
import base64

def encode(key, body, algorithm = 'HS256'):
    # key should be a string.
    # body should be a dict.
    # algorithm should be string matching an algorithm...we're only supporting HS256 right now...don't use it.
    #
    header = {'alg': algorithm}

    headerB = bytes(json.dumps(header), 'utf-8')
    bodyB = bytes(json.dumps(body), 'utf-8')

    headerBE = base64.b64encode(headerB)
    bodyBE = base64.b64encode(bodyB)
    payload = bytes(headerBE.decode('utf-8') + '.' + bodyBE.decode('utf-8'), 'utf-8')
    signature = base64.b64encode(hmac.new(bytes(key, 'utf-8'), payload, digestmod=hashlib.sha256).digest())
    token = payload.decode('utf-8') + '.' + signature.decode('utf-8')

    return token


def validate(token, key, algorithm = 'HS256'):
    # token should be a string.
    # key should be a string.
    # algorithm should be string matching an algorithm...we're only supporting HS256 right now...don't use it.
    #
    token_pieces = token.split('.')

    body = token_pieces[1]
    header = token_pieces[0]

    payload = bytes(header + '.' + body, 'utf-8')
    gen_signature = base64.b64encode(hmac.new(bytes(key, 'utf-8'), payload, digestmod=hashlib.sha256).digest()).decode('utf-8')

    token_is_internally_consistent = gen_signature.replace('=', '') == token_pieces[2].replace('=', '')
    return token_is_internally_consistent


def extractData(token):
    token_pieces = token.split('.')
    body = json.loads(base64.b64decode(token_pieces[1]).decode('utf-8'))
    return body