from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import os

# Inicializace aplikace
app = Flask(__name__)
CORS(app)  # Povolení komunikace mezi frontendem a backendem

# Konfigurace databáze
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///math_tasks.db'
app.config['JWT_SECRET_KEY'] = 'supersecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Model uživatele
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'student' nebo 'teacher'

# Model matematického příkladu
class MathProblem(db.Model):
    __tablename__ = 'math_problem'  
    id = db.Column(db.Integer, primary_key=True)
    difficulty = db.Column(db.String(10), nullable=False)  # 'easy', 'medium', 'hard'
    question = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Model domácího úkolu
class Homework(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    problem_id = db.Column(db.Integer, db.ForeignKey('math_problem.id'), nullable=False) 
    status = db.Column(db.String(20), default='assigned')  # 'assigned', 'submitted', 'graded'
    student_answer = db.Column(db.Text, nullable=True)
    teacher_feedback = db.Column(db.Text, nullable=True)
    grade = db.Column(db.Integer, nullable=True)

# Úvodní route pro testování
@app.route('/', methods=['GET'])
def home():
    return jsonify({'message': 'API is running'}), 200

# API pro registraci uživatele
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Kontrola, zda uživatel už existuje
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'User already exists'}), 400  

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password, role=data['role'])
    
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

# API pro přihlášení uživatele
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if user and bcrypt.check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity={'username': user.username, 'role': user.role})
        return jsonify(access_token=access_token), 200
    return jsonify({'message': 'Invalid credentials'}), 401

# API pro získání seznamu matematických příkladů
@app.route('/problems', methods=['GET'])
def get_problems():
    problems = MathProblem.query.all()
    return jsonify([{
        'id': problem.id,
        'difficulty': problem.difficulty,
        'question': problem.question,
        'answer': problem.answer
    } for problem in problems]), 200

# API pro získání domácích úkolů (chráněné přístupem JWT)
@app.route('/homework', methods=['GET'])
@jwt_required()
def get_homework():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user['username']).first()
    
    if not user:
        return jsonify({'message': 'User not found'}), 404

    homework = Homework.query.filter_by(assigned_to=user.id).all()
    return jsonify([{
        'id': hw.id,
        'question': hw.problem.question,
        'status': hw.status
    } for hw in homework]), 200

# Spuštění aplikace
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=True)
