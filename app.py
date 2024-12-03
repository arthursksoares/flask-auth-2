from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask import make_response
from marshmallow import Schema, fields, validate, ValidationError
from datetime import datetime, timedelta
import secrets
import os
import mysql.connector
from flask_mail import Mail, Message  # Novo import para o envio de e-mails

app = Flask(__name__)

# Configurações de Banco de Dados
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:admin@localhost:3306/auth_system'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=2)
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)

# Configurações de e-mail (substitua pelos dados corretos)
app.config['MAIL_SERVER'] = 'smtp.ethereal.email'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True  # Ativa o TLS (inicia uma conexão segura)
app.config['MAIL_USE_SSL'] = False  # Não usa SSL, usa TLS
app.config['MAIL_USERNAME'] = 'lue.bergstrom74@ethereal.email'  # Substitua pelo seu e-mail
app.config['MAIL_PASSWORD'] = 'z7sBPxgNX9rgH6VdF4'  # Substitua pela sua senha
mail = Mail(app)

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

# Função para enviar e-mail de reset de senha
def send_reset_email(user_email, reset_token):
    reset_url = url_for('reset_password', token=reset_token, _external=True)
    msg = Message('Redefinição de Senha',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user_email])
    msg.body = f'Use o link abaixo para redefinir sua senha:\n\n{reset_url}\n\nSe você não solicitou isso, ignore este e-mail.'
    mail.send(msg)

# Rotas de Autenticação
@app.route('/', methods=['GET'])
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
        # Verifica se o usuário já está logado
    token = request.cookies.get('access_token')
    if token:
        try:
            # Decodifica o token para verificar se é válido
            decoded_token = decode_token(token)
            identity = decoded_token["sub"]
            user = User.query.get(identity)
            
            if user:
                # Se o usuário estiver autenticado, redireciona para a página protegida
                return redirect(url_for('protected'))
        except Exception as e:
            pass  # Se houver um erro no token, deixamos o fluxo continuar e exibir a página de registro

    if request.method == 'POST':
        try:
            # Converte os dados do formulário para dicionário
            data = user_schema.load(request.form.to_dict())

            # Verifica se o usuário ou email já existem
            if User.query.filter_by(username=data['username']).first():
                return render_template('register.html', msg="Username já cadastrado")

            if User.query.filter_by(email=data['email']).first():
                return render_template('register.html', msg="Email já cadastrado")
            
            # Cria o hash da senha
            hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
            
            # Cria um novo usuário
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

from flask import redirect, url_for

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Verifica se o usuário já está logado
    token = request.cookies.get('access_token')
    if token:
        try:
            # Decodifica o token para verificar se é válido
            decoded_token = decode_token(token)
            identity = decoded_token["sub"]
            user = User.query.get(identity)
            
            if user:
                # Se o usuário estiver autenticado, redireciona para a página protegida
                return redirect(url_for('protected'))
        except Exception as e:
            pass  # Se houver um erro no token, deixamos o fluxo continuar e exibir o login

    if request.method == 'POST':
        try:
            data = request.form
            user = User.query.filter_by(username=data.get('username')).first()
            
            if user and bcrypt.check_password_hash(user.password_hash, data.get('password')):
                # Cria o token de acesso com o ID do usuário como 'sub'
                access_token = create_access_token(identity=str(user.id))  # Garantindo que 'sub' seja uma string
                
                # Cria a resposta e armazena o token no cookie
                response = make_response(redirect(url_for('protected')))  # Redireciona para a página protegida
                response.set_cookie('access_token', access_token)  # Armazena o token no cookie
                return response
            
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
                
                # Envia o e-mail com o token de reset
                send_reset_email(user.email, reset_token)
                
                return render_template('reset_password_request.html', msg="Token de reset gerado e enviado por e-mail")
            
            return render_template('reset_password_request.html', msg="Email não encontrado")
        except Exception as e:
            return render_template('reset_password_request.html', msg=str(e))

    return render_template('reset_password_request.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token')  # Obtem o token da URL
    
    if request.method == 'POST':
        try:
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')

            if new_password != confirm_password:
                return render_template('reset_password.html', token=token, msg="As senhas não coincidem")
            
            user = User.query.filter_by(reset_token=token).first()
            
            if user and user.reset_token_expiration > datetime.utcnow():
                hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                user.password_hash = hashed_password
                user.reset_token = None
                user.reset_token_expiration = None
                db.session.commit()
                
                return redirect(url_for('login', msg="Senha resetada com sucesso!"))
            
            return render_template('reset_password.html', token=token, msg="Token inválido ou expirado")
        except Exception as e:
            return render_template('reset_password.html', token=token, msg=str(e))
    
    return render_template('reset_password.html', token=token)  # Token enviado para o formulário

from flask_jwt_extended import decode_token

@app.route('/protected', methods=['GET'])
def protected():
    # Recupera o token do cookie
    token = request.cookies.get('access_token')

    if not token:
        # Redireciona para a tela de login se o token não estiver presente
        return redirect(url_for('login'))

    try:
        # Decodifica o token usando a função correta
        decoded_token = decode_token(token)
        identity = decoded_token["sub"]  # Extrai o ID do usuário
        user = User.query.get(identity)
        
        if not user:
            return jsonify({"msg": "Invalid Token"}), 401

        return render_template('protected.html', username=user.username)

    except Exception as e:
        return jsonify({"msg": "Token validation failed", "error": str(e)}), 401

@app.route('/logout', methods=['POST'])
def logout():
    token = request.cookies.get('access_token')

    if not token:
        # Se não estiver logado, redireciona para a tela de login
        return redirect(url_for('login'))

    # Se estiver logado, realiza o logout
    response = redirect(url_for('login'))
    response.delete_cookie('access_token')
    return response

@app.route('/logout', methods=['GET'])
def logout_get():
    # Caso tente acessar via GET, redireciona para o login ou página de erro
    return redirect(url_for('login'))  # ou retornar uma página de erro personalizada

# Tratamento de erro 404
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Configuração para criar tabelas
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)