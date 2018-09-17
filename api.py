import os
import uuid
import jwt
import datetime

from functools import wraps
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api
from werkzeug.security import generate_password_hash, check_password_hash

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = 'segredo'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'lmao.db')
api = Api(app)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class Ponto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    reason = db.Column(db.String(100))
    status = db.Column(db.String(10))
    user_id = db.Column(db.String(50))
    jamal_id = db.Column(db.String(50))
    votes = db.Column(db.Integer)
    points = db.Column(db.Integer) 


def token_required(fn):
    @wraps(fn)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Cade o token fera? ponto!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Cade o token fera? ponto!'}), 401

        return fn(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Não pode fera, ponto!'})

    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Novo Jamal criado'})

@app.route('/ponto', methods=['POST'])
def create_ponto():
    data = request.get_json()
    new_ponto = Ponto(public_id=str(uuid.uuid4()), reason=data['reason'], status='pendente', user_id=data['user_id'], jamal_id=data['jamal_id'], votes=1, points=data['points'])
    db.session.add(new_ponto)
    db.session.commit()
    return jsonify({'message': 'Novo ponto criado, no aguardo da votação'})

@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message' : 'Não pode fera, ponto!'})
    users = User.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify({'jamals': output  })

@app.route('/pontos', methods=['GET'])
def get_all_pontos():
    pontos = Ponto.query.all()
    output = []
    if not pontos:
        return jsonify({'message': 'Não tem ponto nesse jamal ou jamal com esse id'})
    for ponto in pontos:
        ponto_data = {}
        ponto_data['reason'] = ponto.reason
        output.append(ponto_data)
    return jsonify({'pontos': output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    
    if not current_user.admin:
        return jsonify({'message' : 'Não pode fera, ponto!'})

    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'Não tem jamal com esse id'})
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['admin'] = user.admin
    
    return jsonify({'jamal': user_data})

@app.route('/pontos/<public_id>', methods=['GET'])
def get_one_user_pontos(public_id):

    pontos = Ponto.query.filter_by(jamal_id=public_id)
    if not pontos:
        return jsonify({'message': 'Não tem ponto nesse jamal ou jamal com esse id'})
    output = []
    for ponto in pontos:
        ponto_data = {}
        ponto_data['reason'] = ponto.reason
        ponto_data['points'] = ponto.points
        ponto_data['status'] = ponto.status
        ponto_data['votes'] = ponto.votes
        ponto_data['user_id'] = ponto.user_id
        ponto_data['jamal_id'] = ponto.jamal_id
        output.append(ponto_data)
    return jsonify({'pontos': output})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Não pode fera, ponto!'})
    
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'Não tem jamal com esse id'})
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'Jamal deletado'})

@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Não rolou meu bom, ponto', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    
    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Não rolou meu bom, ponto', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'])

        return jsonify({'token': token.decode('UTF-8')})
    return make_response('Não rolou meu bom, ponto', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

if __name__ == '__main__':
    app.run(debug=True)