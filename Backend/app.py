from flask import Flask, request, jsonify, render_template, redirect, url_for, g
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash
import jwt
import datetime
from functools import wraps
from config import Config
from flask_cors import CORS
from extensions import db, migrate
from flasgger import Swagger
import secrets
import os
import json

from sqlalchemy.sql import text
from datetime import timedelta

# Importar sistema de logging
from logging_utils import (
    log_activity, log_login_attempt, log_logout, log_parametro_alteracao,
    log_acesso_tela, log_crud_operation, registrar_log_atividade
)

from models import User, Item, Leitura, Parametro, Log

# Obtenha o caminho absoluto do diretório onde app.py está (Backend/)
basedir = os.path.abspath(os.path.dirname(__file__))

# Configuração da porta
PORT = int(os.environ.get('PORT', 5001))  # Padrão 5001, mas pode ser sobrescrito

app = Flask(__name__,
          static_folder=os.path.join(basedir, 'static'),
          template_folder=os.path.join(basedir, 'templates'))

CORS(app)
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

app.config.from_object(Config)

db.init_app(app)
migrate.init_app(app, db)

# Configuração do Swagger
swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "Embryotech API  --  Outside Agrotech",
        "description": "API para gerenciamento de usuários, parâmetros e leituras de embriões",
        "contact": {
            "email": "pedro.zaura@outsideagro.tech"
        },
        "version": "1.0.1"
    },
    "basePath": "/",
    "schemes": [
        "http"
    ],
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme. Example: \"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\""
        }
    },
    "security": [
        {
            "Bearer": []
        }
    ]
}

swagger = Swagger(app, template=swagger_template)

# Middleware para logging automático
@app.before_request
def before_request():
    # Registrar acesso apenas se não for um endpoint de API ou static
    if not request.endpoint or request.endpoint.startswith('static'):
        return
    
    # Se for um endpoint de página (não API), registrar acesso
    if request.endpoint in ['login', 'dashboard']:
        user = None
        token = request.cookies.get('embryotech_token') or request.headers.get('Authorization', '').replace('Bearer ', '')
        if token:
            try:
                user = User.verify_auth_token(token, app.config['JWT_SECRET_KEY'])
            except:
                pass
        
        log_acesso_tela(
            usuario=user,
            tela=request.endpoint,
            detalhes_adicionais={
                'user_agent': request.headers.get('User-Agent', ''),
                'ip': request.environ.get('HTTP_X_REAL_IP', request.remote_addr),
                'timestamp': datetime.datetime.utcnow().isoformat()
            }
        )

# Decorator para rotas que requerem autenticação
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            parts = auth_header.split()
            
            if len(parts) == 2 and parts[0].lower() == 'bearer':
                token = parts[1]
            else:
                return jsonify({'message': 'Authorization header must be Bearer token!'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            current_user = User.verify_auth_token(token, app.config['JWT_SECRET_KEY'])
            if not current_user:
                return jsonify({'message': 'Token is invalid!'}), 401
            
            # Adicionar usuário ao contexto global
            g.current_user = current_user
            
        except Exception as e:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# ==================== ROTAS DE PÁGINAS (TEMPLATES) ====================

@app.route('/')
@app.route('/login')
def login():
    """Página de login"""
    logout_success = request.args.get('logout') == 'success'
    return render_template('login.html', logout_success=logout_success)

@app.route('/dashboard')
def dashboard():
    """Dashboard principal - requer autenticação via JavaScript"""
    return render_template('dashboard.html')

# ==================== ROTAS DE API ====================

@app.route('/api/')
@log_activity("API_STATUS_CHECK")
def api_status():
    """
    Endpoint de status da API
    ---
    responses:
      200:
        description: Exibe mensagem de boas-vindas e data/hora do servidor
    """
    try:
        data_hora_db = db.session.execute(text("SELECT CURRENT_TIMESTAMP")).scalar()
        data_hora_ajustada = data_hora_db - timedelta(hours=3)
        return jsonify({
            "mensagem": "Bem-vindo ao Backend do Sistema Embryotech",
            "data_hora": data_hora_ajustada.strftime("%Y-%m-%d %H:%M:%S"),
            "PORTA": PORT,
            "fuso_horario": "GMT-3"
        })
    except Exception as e:
        return jsonify({"erro": f"Erro ao recuperar hora: {str(e)}"}), 500

@app.route('/api/register', methods=['POST'])
@log_activity("USUARIO_REGISTRO")
def api_register():
    """
    Registrar novo usuário
    ---
    tags:
      - Autenticação
    parameters:
      - in: body
        name: body
        required: true
        schema:
          id: UserRegistration
          required:
            - username
            - password
            - email
          properties:
            username:
              type: string
              example: "usuario1"
            password:
              type: string
              example: "senhasegura123"
            email:
              type: string
              example: "usuario@email.com"
    responses:
      201:
        description: Usuário registrado com sucesso
      400:
        description: Campos obrigatórios faltando ou usuário/email já existente
    """
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password') or not data.get('email'):
        log_crud_operation(None, 'users', 'CREATE_FAILED', dados={'erro': 'campos_faltando'})
        return jsonify({'message': 'Missing required fields!'}), 400
    
    if User.query.filter_by(username=data['username']).first():
        log_crud_operation(None, 'users', 'CREATE_FAILED', dados={'erro': 'username_existe', 'username': data['username']})
        return jsonify({'message': 'Username already exists!'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        log_crud_operation(None, 'users', 'CREATE_FAILED', dados={'erro': 'email_existe', 'email': data['email']})
        return jsonify({'message': 'Email already exists!'}), 400
    
    new_user = User(
        username=data['username'],
        email=data['email']
    )
    new_user.set_password(data['password'])
    
    db.session.add(new_user)
    db.session.commit()
    
    log_crud_operation(None, 'users', 'CREATE', dados={'username': data['username'], 'email': data['email']})
    
    return jsonify({'message': 'User registered successfully!'}), 201

@app.route('/api/login', methods=['POST'])
def api_login():
    """
    Login de usuário
    ---
    tags:
      - Autenticação
    parameters:
      - in: body
        name: body
        required: true
        schema:
          id: UserLogin
          required:
            - username
            - password
          properties:
            username:
              type: string
              example: "usuario1"
            password:
              type: string
              example: "senhasegura123"
    responses:
      200:
        description: Login bem-sucedido
        schema:
          properties:
            token:
              type: string
              example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
      400:
        description: Campos obrigatórios faltando
      401:
        description: Credenciais inválidas
    """
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        log_login_attempt('', False, 'campos_faltando')
        return jsonify({'message': 'Missing username or password!'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not user.check_password(data['password']):
        log_login_attempt(data['username'], False, 'credenciais_invalidas')
        return jsonify({'message': 'Invalid username or password!'}), 401
    
    token = user.generate_auth_token(app.config['JWT_SECRET_KEY'])
    log_login_attempt(data['username'], True)
    
    return jsonify({'token': token}), 200

@app.route('/api/logout', methods=['POST'])
@token_required
@log_activity("LOGOUT")
def api_logout(current_user):
    """
    Logout de usuário
    ---
    tags:
      - Autenticação
    security:
      - Bearer: []
    responses:
      200:
        description: Logout realizado com sucesso
    """
    log_logout(current_user)
    return jsonify({'message': 'Logout realizado com sucesso'}), 200

@app.route('/api/leituras', methods=['POST'])
@token_required
@log_activity("CRIAR_LEITURAS")
def api_criar_leitura(current_user):
    """
    Criar novas leituras de embrião (suporte a múltiplas leituras)
    """
    try:
        if not request.is_json:
            return jsonify({'message': 'O corpo da requisição deve ser JSON'}), 400
            
        data = request.get_json()
        
        if not isinstance(data, list):
            data = [data]
        
        leituras = []
        for item in data:
            nova = Leitura(
                umidade=item.get('umidade'),
                temperatura=item.get('temperatura'),
                pressao=item.get('pressao'),
                lote=item.get('lote'),
                data_inicial=item.get('data_inicial'),
                data_final=item.get('data_final')
            )
            leituras.append(nova)
        
        db.session.add_all(leituras)
        db.session.commit()
        
        log_crud_operation(current_user, 'leituras', 'CREATE_BATCH', dados={'quantidade': len(leituras)})
        
        return jsonify({
            'message': f'{len(leituras)} leituras criadas com sucesso',
            'quantidade': len(leituras)
        }), 201
        
    except Exception as e:
        db.session.rollback()
        log_crud_operation(current_user, 'leituras', 'CREATE_FAILED', dados={'erro': str(e)})
        return jsonify({'message': f'Erro ao processar os dados: {str(e)}'}), 400

@app.route('/api/leituras', methods=['GET'])
@token_required
@log_activity("LISTAR_LEITURAS")
def api_listar_leituras(current_user):
    """
    Listar todas as leituras de embriões
    """
    lote = request.args.get('lote')
    
    query = Leitura.query
    
    if lote:
        query = query.filter(Leitura.lote == lote)
    
    leituras = query.order_by(Leitura.data_inicial.desc()).all()
    
    return jsonify([{
        'id': l.id,
        'umidade': l.umidade,
        'temperatura': l.temperatura,
        'pressao': l.pressao,
        'lote': l.lote,
        'data_inicial': l.data_inicial.isoformat() if l.data_inicial else None,
        'data_final': l.data_final.isoformat() if l.data_final else None
    } for l in leituras]), 200

@app.route('/api/leituras/<int:leitura_id>', methods=['PUT'])
@token_required
@log_activity("ATUALIZAR_LEITURA")
def api_atualizar_leitura(current_user, leitura_id):
    """
    Atualizar uma leitura existente
    """
    leitura = Leitura.query.get(leitura_id)
    if not leitura:
        return jsonify({'message': 'Leitura não encontrada'}), 404

    data = request.get_json()
    dados_anteriores = {
        'umidade': leitura.umidade,
        'temperatura': leitura.temperatura,
        'pressao': leitura.pressao,
        'lote': leitura.lote
    }
    
    leitura.umidade = data.get('umidade', leitura.umidade)
    leitura.temperatura = data.get('temperatura', leitura.temperatura)
    leitura.pressao = data.get('pressao', leitura.pressao)
    leitura.lote = data.get('lote', leitura.lote)
    leitura.data_inicial = data.get('data_inicial', leitura.data_inicial)
    leitura.data_final = data.get('data_final', leitura.data_final)

    db.session.commit()
    
    log_crud_operation(current_user, 'leituras', 'UPDATE', leitura_id, 
                      dados={'anteriores': dados_anteriores, 'novos': data})
    
    return jsonify({'message': 'Leitura atualizada com sucesso'}), 200

@app.route('/api/leituras/<int:leitura_id>', methods=['DELETE'])
@token_required
@log_activity("DELETAR_LEITURA")
def api_deletar_leitura(current_user, leitura_id):
    """
    Deletar uma leitura existente
    """
    leitura = Leitura.query.get(leitura_id)
    if not leitura:
        return jsonify({'message': 'Leitura não encontrada'}), 404

    dados_leitura = {
        'id': leitura.id,
        'lote': leitura.lote,
        'temperatura': leitura.temperatura
    }
    
    db.session.delete(leitura)
    db.session.commit()
    
    log_crud_operation(current_user, 'leituras', 'DELETE', leitura_id, dados=dados_leitura)
    
    return jsonify({'message': 'Leitura deletada com sucesso'}), 200

@app.route('/api/parametros', methods=['POST'])
@token_required
@log_activity("CRIAR_PARAMETRO")
def api_criar_parametro(current_user):
    """
    Criar novo conjunto de parâmetros ideais
    """
    if not current_user.is_admin:
        log_crud_operation(current_user, 'parametros', 'CREATE_DENIED', dados={'motivo': 'nao_admin'})
        return jsonify({'message': 'Acesso negado!'}), 403

    data = request.get_json()
    try:
        if not all([data.get('empresa'), data.get('lote'), data.get('temp_ideal'), data.get('umid_ideal')]):
            return jsonify({'message': 'Empresa, lote, temperatura e umidade são obrigatórios'}), 400

        novo_parametro = Parametro(
            empresa=data['empresa'],
            lote=data['lote'],
            temp_ideal=data['temp_ideal'],
            umid_ideal=data['umid_ideal'],
            pressao_ideal=data.get('pressao_ideal'),
            lumens=data.get('lumens'),
            id_sala=data.get('id_sala'),
            estagio_ovo=data.get('estagio_ovo')
        )
        db.session.add(novo_parametro)
        db.session.commit()
        
        log_crud_operation(current_user, 'parametros', 'CREATE', novo_parametro.id, 
                          dados={'empresa': data['empresa'], 'lote': data['lote']})
        
        return jsonify({
            'message': 'Parâmetro criado com sucesso!',
            'parametro': novo_parametro.to_dict()
        }), 201
    except Exception as e:
        db.session.rollback()
        log_crud_operation(current_user, 'parametros', 'CREATE_FAILED', dados={'erro': str(e)})
        return jsonify({'message': f'Erro ao salvar parâmetro: {str(e)}'}), 400

@app.route('/api/empresas', methods=['GET'])
@token_required
@log_activity("LISTAR_EMPRESAS")
def api_get_empresas(current_user):
    """
    Obter lista de empresas cadastradas
    """
    if not current_user.is_admin:
        return jsonify({'message': 'Acesso negado!'}), 403
    
    empresas = db.session.query(Parametro.empresa).distinct().all()
    return jsonify([e[0] for e in empresas if e[0]]), 200

@app.route('/api/lotes', methods=['GET'])
@token_required
@log_activity("LISTAR_LOTES")
def api_get_lotes(current_user):
    """
    Obter lista de todos os lotes (ou filtrado por empresa)
    """
    empresa = request.args.get('empresa')
    
    query = db.session.query(Parametro.lote).distinct()
    if empresa:
        query = query.filter_by(empresa=empresa)
    
    lotes = query.all()
    return jsonify([l[0] for l in lotes if l[0]]), 200

@app.route('/api/parametros', methods=['GET'])
@token_required
@log_activity("BUSCAR_PARAMETROS")
def api_get_parametros(current_user):
    """
    Buscar parâmetros por empresa e lote
    """
    if not current_user.is_admin:
        return jsonify({'message': 'Acesso negado!'}), 403

    empresa = request.args.get('empresa')
    lote = request.args.get('lote')

    if not empresa or not lote:
        return jsonify({'message': 'Empresa e lote são obrigatórios'}), 400

    parametros = Parametro.query.filter_by(empresa=empresa, lote=lote).all()

    return jsonify([p.to_dict() for p in parametros]), 200

@app.route('/api/parametros/<int:id>', methods=['PUT'])
@token_required
@log_activity("ATUALIZAR_PARAMETRO")
def api_atualizar_parametro(current_user, id):
    """
    Atualizar parâmetros existentes
    """
    if not current_user.is_admin:
        return jsonify({'message': 'Acesso negado!'}), 403

    parametro = Parametro.query.get(id)
    if not parametro:
        return jsonify({'message': 'Parâmetro não encontrado'}), 404

    data = request.get_json()
    dados_anteriores = parametro.to_dict()
    
    try:
        if 'empresa' in data:
            parametro.empresa = data['empresa']
        if 'lote' in data:
            parametro.lote = data['lote']
        if 'temp_ideal' in data:
            parametro.temp_ideal = data['temp_ideal']
        if 'umid_ideal' in data:
            parametro.umid_ideal = data['umid_ideal']
        if 'pressao_ideal' in data:
            parametro.pressao_ideal = data.get('pressao_ideal')
        if 'lumens' in data:
            parametro.lumens = data.get('lumens')
        if 'id_sala' in data:
            parametro.id_sala = data.get('id_sala')
        if 'estagio_ovo' in data:
            parametro.estagio_ovo = data.get('estagio_ovo')

        db.session.commit()
        
        log_parametro_alteracao(current_user, id, dados_anteriores, parametro.to_dict(), 'UPDATE')
        
        return jsonify({
            'message': 'Parâmetro atualizado com sucesso!',
            'parametro': parametro.to_dict()
        }), 200
    except Exception as e:
        db.session.rollback()
        log_crud_operation(current_user, 'parametros', 'UPDATE_FAILED', id, dados={'erro': str(e)})
        return jsonify({'message': f'Erro ao atualizar parâmetro: {str(e)}'}), 400

@app.route('/api/logs', methods=['GET'])
@token_required
@log_activity("CONSULTAR_LOGS")
def api_get_logs(current_user):
    """
    Consultar logs do sistema (apenas para administradores)
    """
    if not current_user.is_admin:
        return jsonify({'message': 'Acesso negado!'}), 403
    
    # Parâmetros de filtro
    usuario_id = request.args.get('usuario_id', type=int)
    acao = request.args.get('acao')
    data_inicio = request.args.get('data_inicio')
    data_fim = request.args.get('data_fim')
    limite = request.args.get('limite', 100, type=int)
    
    query = Log.query
    
    if usuario_id:
        query = query.filter(Log.usuario_id == usuario_id)
    if acao:
        query = query.filter(Log.acao.contains(acao))
    if data_inicio:
        query = query.filter(Log.data_hora >= data_inicio)
    if data_fim:
        query = query.filter(Log.data_hora <= data_fim)
    
    logs = query.order_by(Log.data_hora.desc()).limit(limite).all()
    
    return jsonify([log.to_dict() for log in logs]), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=True)