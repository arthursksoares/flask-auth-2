# Arquivo: app.py
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from marshmallow import Schema, fields, validate, ValidationError
from datetime import datetime, timedelta
import secrets
import os
import mysql.connector

app = Flask(__name__)

# Configurações de Banco de Dados
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:admin@localhost:3306/auth_system'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=2)
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Modelo de Usuário
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    reset_token = db.Column(db.String(255), nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)

# Schemas de Validação
class UserSchema(Schema):
    username = fields.Str(required=True, validate=[
        validate.Length(min=3, max=50),
        validate.Regexp(r'^[a-zA-Z0-9_]+$', error='Username deve conter apenas letras, números e underscore')
    ])
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=[
        validate.Length(min=8, error='Senha deve ter no mínimo 8 caracteres'),
        validate.Regexp(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$', 
                        error='Senha deve conter letra, número e caractere especial')
    ])

user_schema = UserSchema()

# Rotas de Autenticação
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            # Valida dados de entrada
            data = user_schema.load(request.form)
            
            # Verifica se usuário já existe
            if User.query.filter_by(username=data['username']).first():
                return render_template('register.html', msg="Username já cadastrado")

            if User.query.filter_by(email=data['email']).first():
                return render_template('register.html', msg="Email já cadastrado")
            
            # Cria hash da senha
            hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
            
            # Cria novo usuário
            new_user = User(
                username=data['username'], 
                email=data['email'], 
                password_hash=hashed_password
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            return redirect(url_for('login'))
        
        except ValidationError as err:
            return render_template('register.html', msg=err.messages)
        except Exception as e:
            return render_template('register.html', msg=str(e))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            data = request.form
            user = User.query.filter_by(username=data.get('username')).first()
            
            if user and bcrypt.check_password_hash(user.password_hash, data.get('password')):
                access_token = create_access_token(identity=user.id)
                return render_template('protected.html', username=user.username, token=access_token)
            
            return render_template('login.html', msg="Credenciais inválidas")
        except Exception as e:
            return render_template('login.html', msg=str(e))

    return render_template('login.html')

@app.route('/reset-password-request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            user = User.query.filter_by(email=email).first()
            
            if user:
                reset_token = secrets.token_urlsafe(32)
                user.reset_token = reset_token
                user.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)
                db.session.commit()
                
                # Aqui você implementaria o envio de email
                # send_reset_email(user.email, reset_token)
                
                return render_template('reset_password_request.html', msg="Token de reset gerado")
            
            return render_template('reset_password_request.html', msg="Email não encontrado")
        except Exception as e:
            return render_template('reset_password_request.html', msg=str(e))

    return render_template('reset_password_request.html')

@app.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        token = request.form.get('token')
        new_password = request.form.get('new_password')
        
        user = User.query.filter_by(reset_token=token).first()
        
        if user and user.reset_token_expiration > datetime.utcnow():
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user.password_hash = hashed_password
            user.reset_token = None
            user.reset_token_expiration = None
            db.session.commit()
            
            return render_template('reset_password.html', msg="Senha resetada com sucesso")
        
        return render_template('reset_password.html', msg="Token inválido ou expirado")
    except Exception as e:
        return render_template('reset_password.html', msg=str(e))

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    return render_template('protected.html', username=user.username)

# Configuração para criar tabelas
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
