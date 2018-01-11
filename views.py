from flask import request, jsonify, make_response, \
                    redirect, url_for, render_template
from werkzeug.security import generate_password_hash, \
                                check_password_hash
from datetime import datetime, timedelta
from functools import wraps
from app import app
from models import *
import uuid
import jwt


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()

        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/', methods=['GET'])
def landing_page():
    return render_template('index.html')


@app.route('/api/v1/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    '''
    Fetches all users if admin user
    '''

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['email'] = user.email
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users': output})


@app.route('/api/v1/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    '''
    Fetches one users if admin user
    '''
    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['email'] = user.email
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user': user_data})


@app.route('/api/v1/user', methods=['POST'])
def create_user(current_user):
    '''
    Creates a new activity
    '''

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(
        public_id=str(uuid.uuid4()),
        name=data['name'],
        email=data['email'],
        password=hashed_password,
        admin=False)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'messge': 'New user created!'})


@app.route('/api/v1/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    '''
    Admin user (curent user) promotes another user (public id) to admin user
    '''

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'User has been promoted'})


@app.route('/api/v1/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    '''
    Admin user deletes another user
    '''

    if not current_user.admin:
        return jsonify({'message': 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message': 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted!'})


@app.route('/api/v1/login')
def login():
    '''
    Login if user is already registered
    '''
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response(
            'Could not verify', 401, {
                'WWW-Authenticate': 'Basic realm="Login required!"'
            })

    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response(
            'Could not verify', 401, {
                'WWW-Authenticate': 'Basic realm="Login required!"'
            })

    if check_password_hash(user.password, auth.password):
        token = jwt.encode(
            {
                'public_id': user.public_id,
                'exp': datetime.utcnow() + timedelta(minutes=240)
            },
            app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')})

    return make_response('Could not verify', 401, {
        'WWW-Authenticate': 'Basic realm="Login required!"'
    })


@app.route('/api/v1/register', methods=['POST'])
def register():
    '''
    Registers a new user: name, email and password required
    '''

    data = request.get_json()

    user = User.query.filter_by(email=data['email']).first()

    if not user:

        hashed_password = generate_password_hash(
            data['password'], method='sha256')

        new_user = User(
            public_id=str(uuid.uuid4()),
            name=data['name'],
            email=data['email'],
            password=hashed_password,
            admin=False)

        db.session.add(new_user)
        db.session.commit()

        user = User.query.filter_by(email=data['email']).first()

        token = jwt.encode(
            {
                'public_id': user.public_id,
                'exp': datetime.utcnow() + timedelta(minutes=240)
            },
            app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')})

    return jsonify({'message': 'User with that email already exists!'})


@app.route('/api/v1/weights', methods=['GET'])
@token_required
def get_all_weights(current_user):
    '''
    Fetches all weights for current user
    '''

    weights = Weights.query.filter_by(user_id=current_user.id).all()

    output = []

    for weight in weights:
        weight_data = {}
        weight_data['id'] = weight.id
        weight_data['activity'] = weight.activity
        weight_data['weight'] = weight.weight
        weight_data['reps'] = weight.reps
        weight_data['units'] = weight.units
        output.append(weight_data)

    return jsonify({'weights': output})


@app.route('/api/v1/weights/<weight_id>', methods=['GET'])
@token_required
def get_one_weight(current_user, weight_id):
    '''
    Fetches single specified weight by id 
    '''

    output = []

    weight = Weights.query.filter_by(
        id=weight_id, user_id=current_user.id).first()

    if not weight:
        return jsonify({'message': 'No weight found for this activity found!'})

    weight_data = {}
    weight_data['activity'] = weight.activity
    weight_data['weight'] = weight.weight
    weight_data['reps'] = weight.reps
    weight_data['units'] = weight.units
    output.append(weight_data)

    return jsonify({'weight': output})


@app.route('/api/v1/weights', methods=['POST'])
@token_required
def create_weight(current_user):
    '''
    Creates a new weight activity for current user
    '''

    data = request.get_json()

    new_weight = Weights(
        user_id=current_user.id,
        activity=data['activity'],
        weight=data['weight'],
        reps=data['reps'],
        units=data['units'])

    db.session.add(new_weight)
    db.session.commit()

    return jsonify({'messge': 'New weight created for this activity!'})


@app.route('/api/v1/weights/<weight_id>', methods=['DELETE'])
@token_required
def delete_weights(current_user, weight_id):
    '''
    Deletes weight activity for current user by weight id
    '''

    weight = Weights.query.filter_by(
        id=weight_id, user_id=current_user.id).first()

    if not weight:
        return jsonify({'message': 'No weight found for this activity found!'})

    db.session.delete(weight)
    db.session.commit()

    return jsonify({
        'message': 'The weight for this activity has been deleted!'
    })


@app.route('/api/v1/times', methods=['GET'])
@token_required
def get_all_times(current_user):
    '''
    Fetches all times for current user
    '''

    times = Times.query.filter_by(user_id=current_user.id).all()

    output = []

    for time in times:
        time_data = {}
        time_data['id'] = time.id
        time_data['activity'] = time.activity
        time_data['time'] = time.time
        time_data['distance'] = time.distance
        time_data['units'] = time.units
        output.append(time_data)

    return jsonify({'times': output})


@app.route('/api/v1/times/<time_id>', methods=['GET'])
@token_required
def get_one_times(current_user, time_id):
    '''
    Fetches single activity time for current user by time id
    '''

    output = []

    times = Times.query.filter_by(id=time_id, user_id=current_user.id).first()

    if not times:
        return jsonify({'message': 'No times found for this activity found!'})

    times_data = {}
    times_data['activity'] = times.activity
    times_data['time'] = times.time
    times_data['distance'] = times.distance
    times_data['units'] = times.units
    output.append(times_data)

    return jsonify({'times': output})


@app.route('/api/v1/times', methods=['POST'])
@token_required
def create_time(current_user):
    '''
    Creates a time activity for current user
    '''

    data = request.get_json()

    new_time = Times(
        user_id=current_user.id,
        activity=data['activity'],
        time=data['time'],
        distance=data['distance'],
        units=data['units'])

    db.session.add(new_time)
    db.session.commit()

    return jsonify({'messge': 'New time created for this activity!'})


@app.route('/api/v1/times/<time_id>', methods=['DELETE'])
@token_required
def delete_time(current_user, time_id):
    '''
    Deletes time activity for current user by time id
    '''

    time = Times.query.filter_by(id=time_id, user_id=current_user.id).first()

    if not time:
        return jsonify({'message': 'No time found for this activity found!'})

    db.session.delete(time)
    db.session.commit()

    return jsonify({'message': 'The time for this activity has been deleted!'})
