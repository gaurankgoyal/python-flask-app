from flask import Blueprint, jsonify, request, make_response
from flaskblog.models import User
from flaskblog import bcrypt, db
import datetime
import os
import jwt
from flaskblog.decorators import token_required


users_api = Blueprint('users_api', __name__)


@users_api.route('/users')
@token_required
def users(current_user):
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['username'] = user.username
        user_data['email'] = user.email
        user_data['image name'] = user.image_file
        user_data['password'] = user.password
        output.append(user_data)
    return jsonify({'users': output})


@users_api.route('/login_api')
def login_api():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(email=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if bcrypt.check_password_hash(user.password, auth.password):
        token = jwt.encode({'email' : user.email, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}
                           , os.environ.get('SECRET_KEY'))

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})


@users_api.route('/user', methods=['DELETE'])
@token_required
def delete_user(current_user):
    if current_user.email == 'god@gmail.com':
        data = request.get_json()
        email=data['email']
        user = User.query.filter_by(email=email).first()
        db.session.delete(user)
        db.session.commit()
        return jsonify({'messgae': 'User has been Deleted! '})
    return jsonify({'message': 'Cannot perform that function! Insufficient Permission'})






