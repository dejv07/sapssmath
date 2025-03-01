from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from flask_cors import CORS


import os

app = Flask(__name__)
CORS(app)  # Povolení CORS pro frontend

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///math_tasks.db'
app.config['JWT_SECRET_KEY'] = 'supersecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'student' nebo 'teacher'

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password, role=data['role'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity={'username': user.username, 'role': user.role})
        return jsonify(access_token=access_token), 200
    return jsonify({'message': 'Invalid credentials'}), 401
    
@app.route('/', methods=['GET'])
def home():
    return jsonify({'message': 'API is running'}), 200
    @app.route('/problems', methods=['GET'])
def get_problems():
    problems = MathProblem.query.all()
    return jsonify([{
        'id': problem.id,
        'difficulty': problem.difficulty,
        'question': problem.question,
        'answer': problem.answer
    } for problem in problems]), 200

@app.route('/homework', methods=['GET'])
@jwt_required()
def get_homework():
    current_user = get_jwt_identity()
    homework = Homework.query.filter_by(assigned_to=current_user['username']).all()
    return jsonify([{
        'id': hw.id,
        'question': hw.problem.question,
        'status': hw.status
    } for hw in homework]), 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=True)

