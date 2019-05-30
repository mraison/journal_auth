from flask import Flask, abort
# from flask_jwt import JWT, jwt_required, current_identity
from werkzeug.security import safe_str_cmp
from functools import wraps


import os
from flask import Flask, jsonify, request
from flask_cors import CORS
from . import db

from .modules import jwt


JWT_SECRET = 'secret'

#######################################################
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

            return f(body, *args, **kws)
        return decorated_function
    return decorator

# http://flask.pocoo.org/docs/1.0/tutorial/database/
def create_app(test_config=None):
    """Create and configure an instance of the Flask application."""
    app = Flask(__name__)
    app.config.from_mapping(
        # a default secret that should be overridden by instance config
        SECRET_KEY='dev',
        # store the database in the instance folder
        DATABASE=os.path.join(app.instance_path, '../../journal_proj/instance/records.sqlite'),
    )
    # app.debug = True
    # app.config['SECRET_KEY'] = 'super-secret'
    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.update(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # register the database commands
    db.init_app(app)
    # Cors stuff
    cors = CORS(app, resources={r'/*': {'origins': '*'}}, headers='Content-Type', )

    @app.route('/jwt_healthcheck', methods=['GET'])
    @check_jwt(app.config['SECRET_KEY'])
    def jwt_healthcheck(body):
        return jsonify(body), 200


    @app.route('/request_jwt', methods=['POST'])
    def request_jwt():
        ## handle the post data
        req_data = request.get_json()
        try:
            username = req_data['username'] # string
            password = req_data['password'] # string
        except KeyError:
            return jsonify({'error_detail': 'Missing required field'}), 400

        ## look for the user in the DB:
        try:
            cursor = db.get_db().cursor()

            result = cursor.execute(
                'SELECT 1 '
                'FROM users '
                'WHERE username = ? AND password = ?',
                (username, password,)
            ).fetchone()
            cursor.close()

            # @todo add check that query was successful
        except Exception as e:
            return jsonify({'error_detail': str(e)}), 400

        if result is None:
            return jsonify({'error_detail': 'User not found'}), 404

        ### There ya go I made my own fuckin token...
        key = app.config['SECRET_KEY']
        body = {
            'username': username,
            'role': 'user'
        }

        token = jwt.encode(key, body, 'HS256')
        return jsonify({'bearer_token': token}), 200


    @app.route('/user', methods=['POST'])
    def create_user():
        req_data = request.get_json()

        try:
            ## @todo add an http level encryption thing so that password can be transmitted safely.
            username = req_data['username']  # string
            password = req_data['password']  # string
        except KeyError:
            return jsonify({'error_detail': 'Missing required field'}), 400

        try:
            cursor = db.get_db().cursor()

            cursor.execute(
                'INSERT INTO users (username, password) '
                'Values(?, ?)',
                ## @todo add salt encryption here.
                (username, password,)
            )
            id = cursor.lastrowid
            cursor.close()
            db.get_db().commit()
        except Exception as e:
            return jsonify({'error_detail': str(e)}), 400

        data = {'ID': id}
        return jsonify(data), 200

    @app.route('/user', methods=['DELETE'])
    def delete_user():
        req_data = request.get_json()

        ## get the post params
        try:
            ## @todo add an http level encryption thing so that password can be transmitted safely.
            username = req_data['username']  # string
            password = req_data['password']  # string
        except KeyError:
            return jsonify({'error_detail': 'Missing required field'}), 400

        ## check login credentials are legit (we're making the user enter their username and password again to delete.)
        try:
            cursor = db.get_db().cursor()

            result = cursor.execute(
                'SELECT ID '
                'FROM users '
                'WHERE username LIKE ? AND password LIKE ?',
                ## @todo add salt encryption here.
                (username, password,)
            ).fetchone()
            cursor.close()
        except Exception as e:
            return jsonify({'error_detail': str(e)}), 400

        if result is None:
            return jsonify({'error_detail': 'User not found'}), 404

        ## should probably check if ID exists here just in case nothing is found...
        id = dict(zip([key[0] for key in cursor.description], result))['ID']

        ## now do the actual delete
        try:
            cursor = db.get_db().cursor()

            result = cursor.execute(
                'DELETE FROM users '
                'WHERE ID = ?',
                ## @todo add salt encryption here.
                (id,)
            )
            cursor.close()
            db.get_db().commit()
        except Exception as e:
            return jsonify({'error_detail': str(e)}), 400

        if result.rowcount == 0:
            return jsonify({'error_detail': 'User could not be deleted'}), 404

        return jsonify({}), 200

    # Note: Must set the content type to JSON. Use something like:
    # curl -X POST -H "Content-Type: application/json" --data '{"first_name": "Joe", "last_name": "Smith"}' http://localhost:5000/doctors
    @app.route('/user', methods=['PUT'])
    def update_user():
        req_data = request.get_json()

        ## get the post params
        try:
            ## @todo add an http level encryption thing so that password can be transmitted safely.
            username = req_data['username']  # string
            password = req_data['password']  # string
            newPassword = req_data['newPassword'] # string
        except KeyError:
            return jsonify({'error_detail': 'Missing required field'}), 400

        ## check login credentials are legit (we're making the user enter their username and password again to delete.)
        try:
            cursor = db.get_db().cursor()

            result = cursor.execute(
                'SELECT ID '
                'FROM users '
                'WHERE username LIKE ? AND password LIKE ?',
                ## @todo add salt encryption here.
                (username, password,)
            ).fetchone()
            cursor.close()
        except Exception as e:
            return jsonify({'error_detail': str(e)}), 400

        if result is None:
            return jsonify({'error_detail': 'User not found'}), 404

        ## should probably check if ID exists here just in case nothing is found...
        id = dict(zip([key[0] for key in cursor.description], result))['ID']

        try:
            cursor = db.get_db().cursor()

            result = cursor.execute(
                'UPDATE users '
                'SET password = ? '
                'WHERE ID = ?',
                (newPassword, id)
            )

            cursor.close()
            db.get_db().commit()
        except Exception as e:
            return jsonify({'error_detail': str(e)}), 400

        if result.rowcount == 0:
            return jsonify({'error_detail': 'User could not be updated.'}), 404

        return jsonify({}), 200

    return app

