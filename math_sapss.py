from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt, get_jwt_identity
from flask_cors import CORS
from flask_cors import cross_origin
import os

# Inicializace aplikace

app = Flask(__name__)
CORS(app, supports_credentials=True, allow_headers=["Content-Type", "Authorization"], expose_headers="Authorization")


# Konfigurace databáze
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///math_tasks.db'
app.config['JWT_SECRET_KEY'] = 'supersecretkey'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

@app.after_request
def after_request(response):
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
    return response


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
    difficulty = db.Column(db.String(10), nullable=False)
    question = db.Column(db.Text, nullable=False)
    answer = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Model domácího úkolu
class Homework(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    problem_id = db.Column(db.Integer, db.ForeignKey('math_problem.id'), nullable=False)
    status = db.Column(db.String(20), default='assigned')
    student_answer = db.Column(db.Text, nullable=True)
    teacher_feedback = db.Column(db.Text, nullable=True)
    grade = db.Column(db.Integer, nullable=True)

# API testovací route
@app.route('/', methods=['GET'])
def home():
    return jsonify({'message': 'API is running'}), 200

# API pro registraci uživatele
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

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
        access_token = create_access_token(
            identity=user.username,
            additional_claims={"role": user.role}
        )
        return jsonify(access_token=access_token), 200
    return jsonify({'message': 'Invalid credentials'}), 401

# API pro získání matematických příkladů
@app.route('/problems', methods=['GET'])
def get_problems():
    problems = MathProblem.query.all()
    return jsonify([{
        'id': problem.id,
        'difficulty': problem.difficulty,
        'question': problem.question,
        'answer': problem.answer
    } for problem in problems]), 200

# API pro získání domácích úkolů
@app.route('/homework', methods=['GET'])
@jwt_required()
def get_homework():
    current_user = get_jwt_identity()
    current_role = get_jwt()['role']

    user = User.query.filter_by(username=current_user).first()
    
    if not user:
        return jsonify({'message': 'User not found'}), 404

    homework_list = Homework.query.filter_by(assigned_to=user.id).all()
    
    return jsonify([{
        'id': hw.id,
        'question': MathProblem.query.get(hw.problem_id).question,
        'status': hw.status
    } for hw in homework_list]), 200

@app.route('/add_problem', methods=['POST'])
@jwt_required()
@cross_origin()  # Povolení CORS pro tuto API cestu
def add_problem():
    data = request.get_json()

    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()

    if user.role != "teacher":
        return jsonify({'message': 'Only teachers can add problems'}), 403

    new_problem = MathProblem(
        difficulty=data['difficulty'],
        question=data['question'],
        answer=data['answer'],
        created_by=user.id
    )

    db.session.add(new_problem)
    db.session.commit()
    return jsonify({'message': 'Problem added successfully'}), 201
    
# Spuštění aplikace
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=True)
