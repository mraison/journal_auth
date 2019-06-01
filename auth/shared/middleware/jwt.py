from flask import Flask, abort, request, jsonify
from functools import wraps
from ..utils import jwt

def check_jwt(key):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kws):
            if not 'Authorization' in request.headers:
                abort(401)

            user = None
            data = request.headers['Authorization'].encode('ascii', 'ignore')
            decodedToken = None
            token = str.replace(str(data), 'Bearer ', '')
            ## I've gotta trim this fucking byte syntax stuff off....
            token = str.replace(str(token), 'b\'', '')
            token = str.replace(str(token), '\'', '')

            if not jwt.validate(token, key):
                abort(401)

            body = jwt.extractData(token)

            return f(jwt_body=body, *args, **kws)
        return decorated_function

    return decorator
