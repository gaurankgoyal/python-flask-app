from functools import wraps
from flask import request, jsonify
from flaskblog.models import User
import jwt
import os


def token_required(f):
    @wraps(f)
    def wrapper_decorator(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is Missing!'}), 401

        try:
            data = jwt.decode(token, os.environ.get('SECRET_KEY'))
            current_user = User.query.filter_by(email=data['email']).first()
        except:
            return jsonify({'message': 'Token is Invalid'}), 401

        return f(current_user, *args, **kwargs)

    return wrapper_decorator
