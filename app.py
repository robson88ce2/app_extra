from urllib.parse import quote_plus
import streamlit as st
import psycopg2
import bcrypt
from fpdf import FPDF
import pandas as pd
from datetime import datetime, date
import os
from sqlalchemy import create_engine
from psycopg2.pool import ThreadedConnectionPool # Importa o pool de conexões
import functools
import time

# =====================================================
# CONFIGURAÇÕES INICIAIS E CONSTANTES
# =====================================================
try:
    db_secrets = st.secrets["database"]
    db_user = db_secrets["user"]
    db_password_raw = db_secrets["password"]
    db_host = db_secrets["host"]
    db_port = db_secrets["port"]
    db_name = db_secrets["name"]
    db_password_encoded = quote_plus(db_password_raw)
    DATABASE_URL = (
        f"postgresql://{db_user}:{db_password_encoded}@{db_host}:{db_port}/{db_name}"
    )
except KeyError as e:
    st.error(f"Erro: Chave de segredo do banco de dados ausente. Verifique seu arquivo .streamlit/secrets.toml. Detalhes: {e}")
    st.stop()
except Exception as e:
    st.error(f"Erro inesperado ao carregar configurações do banco de dados: {e}")
    st.stop()

# Engine para uso com pandas e SQLAlchemy (usa seu próprio pool de conexões)
db_engine = create_engine(DATABASE_URL)

# Pool de conexões para psycopg2 (para operações que não usam pandas/SQLAlchemy)
connection_pool = None

def initialize_connection_pool():
    """Inicializa o pool de conexões psycopg2."""
    global connection_pool
    if connection_pool is None:
        try:
            connection_pool = ThreadedConnectionPool(
                minconn=1,  # Mínimo de conexões ociosas
                maxconn=10, # Máximo de conexões (ajuste conforme a carga esperada)
                dsn=DATABASE_URL
            )
            return True
        except Exception as e:
            st.error(f"Erro ao inicializar pool de conexões: {e}")
            return False
    return True # Já inicializado

def get_connection():
    """Obtém uma conexão do pool."""
    if connection_pool is None:
        if not initialize_connection_pool():
            raise Exception("Pool de conexões não inicializado.")
    return connection_pool.getconn()

def release_connection(conn):
    """Devolve uma conexão ao pool."""
    if connection_pool and conn:
        connection_pool.putconn(conn)

LOGO_EMOJI = "🚔"
ADMIN_COLOR = "#1f77b4"
USER_COLOR = "#2ca02c"

# Compatibilidade rerun (Safe)
if not hasattr(st, "rerun"):
    if hasattr(st, "experimental_rerun"):
        st.rerun = st.experimental_rerun

# Configuração da página
st.set_page_config(
    page_title="Sistema de Escala Policial",
    page_icon="🚔",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS personalizado
st.markdown("""
<style>
    /* Sidebar personalizada */
    .css-1d391kg {
        background-color: #f0f2f6;
    }
    /* Headers personalizados */
    .main-header {
        background: linear-gradient(90deg, #1e3a8a, #3b82f6);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        margin-bottom: 2rem;
    }
    .section-header {
        background-color: #f8fafc;
        padding: 0.8rem;
        border-left: 4px solid #3b82f6;
        margin: 1rem 0;
        border-radius: 5px;
    }
    /* Cards informativos */
    .info-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
    }
    .warning-card {
        background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
    }
    .success-card {
        background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
    }
    .suggestion-card {
        background: linear-gradient(135deg, #a8edea 0%, #fed6e3 100%);
        color: #2d3748;
        padding: 1rem;
        border-radius: 10px;
        margin: 0.5rem 0;
        border: 2px solid #38b2ac;
    }
    /* Botões customizados */
    .stButton > button {
        border-radius: 20px;
        border: none;
        padding: 0.5rem 1rem;
        font-weight: 600;
        transition: all 0.3s;
    }
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    }
    /* Métricas personalizadas */
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 10px;
        border: 1px solid #e2e8f0;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        text-align: center;
    }
    /* Alertas personalizados */
    .alert-info {
        background-color: #e3f2fd;
        border-left: 4px solid #2196f3;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    .alert-success {
        background-color: #e8f5e8;
        border-left: 4px solid #4caf50;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# =====================================================
# FUNÇÕES UTILITÁRIAS
# =====================================================

# Decorador de cache com tempo de vida para funções que não são do Streamlit
def timed_cache(seconds=300):
    def decorator(func):
        cache_data = {'value': None, 'last_update': 0}

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            if now - cache_data['last_update'] > seconds:
                value = func(*args, **kwargs)
                cache_data['value'] = value
                cache_data['last_update'] = now
                return value
            return cache_data['value']

        def clear_cache():
            cache_data['value'] = None
            cache_data['last_update'] = 0

        wrapper.clear_cache = clear_cache
        return wrapper
    return decorator

@functools.lru_cache(maxsize=100) # Cache para conversões de data
def iso_to_display(d):
    """Converte 'YYYY-MM-DD' -> 'dd/mm/yyyy'. Se já for None/vazio, retorna '-'"""
    try:
        if not d:
            return "-"
        if isinstance(d, datetime) or isinstance(d, date):
            return d.strftime("%d/%m/%Y")
        return datetime.strptime(d, "%Y-%m-%d").strftime("%d/%m/%Y")
    except Exception:
        return d

def display_to_iso(d: date):
    """Recebe um objeto date do streamlit e retorna 'YYYY-MM-DD'"""
    if isinstance(d, date):
        return d.strftime("%Y-%m-%d")
    try:
        return datetime.strptime(d, "%d/%m/%Y").strftime("%Y-%m-%d")
    except Exception:
        return d

def show_metric_card(title, value, subtitle=""):
    """Exibe um card de métrica personalizado"""
    st.markdown(f"""
    <div class="metric-card">
        <h3 style="margin: 0; color: #1e3a8a;">{value}</h3>
        <p style="margin: 0; font-weight: 600; color: #64748b;">{title}</p>
        <small style="color: #94a3b8;">{subtitle}</small>
    </div>
    """, unsafe_allow_html=True)

@st.cache_data(ttl=60) # Cache para a sugestão de horas
def calcular_sugestao_horas():
    """Calcula sugestão de divisão equilibrada de horas"""
    conn = None
    try:
        conn = get_connection()
        c = conn.cursor()
        
        # Total de horas disponíveis
        c.execute("SELECT SUM(horas) as total_horas FROM turnos WHERE ativo=TRUE")
        total_horas_turnos = c.fetchone()[0] or 0
        
        # Número total de policiais (excluindo admin)
        c.execute("SELECT COUNT(*) as total_policiais FROM usuarios WHERE primeiro_nome != 'admin' AND ativo=TRUE")
        total_policiais = c.fetchone()[0] or 1
        
        # Horas já alocadas
        c.execute("SELECT SUM(horas) as horas_alocadas FROM turnos WHERE reservado_por IS NOT NULL AND ativo=TRUE")
        horas_alocadas = c.fetchone()[0] or 0
        
        # Cálculos
        horas_disponiveis = total_horas_turnos - horas_alocadas
        sugestao_por_policial = round(horas_disponiveis / total_policiais) if total_policiais > 0 else 0
        sugestao_equilibrada = round(total_horas_turnos / total_policiais) if total_policiais > 0 else 0
        
        return {
            'total_horas_turnos': total_horas_turnos,
            'total_policiais': total_policiais,
            'horas_alocadas': horas_alocadas,
            'horas_disponiveis': horas_disponiveis,
            'sugestao_por_policial': sugestao_por_policial,
            'sugestao_equilibrada': sugestao_equilibrada
        }
    except psycopg2.Error as e:
        st.error(f"Erro ao calcular sugestão de horas: {e}")
        return {
            'total_horas_turnos': 0, 'total_policiais': 1, 'horas_alocadas': 0,
            'horas_disponiveis': 0, 'sugestao_por_policial': 0, 'sugestao_equilibrada': 0
        }
    finally:
        if conn:
            release_connection(conn)

def verificar_primeiro_login(user_id):
    """Verifica se é o primeiro login do usuário"""
    conn = None
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT primeiro_login FROM usuarios WHERE id=%s", (user_id,))
        result = c.fetchone()
        return result is None or result[0] is None or result[0] == True # PostgreSQL stores TRUE/FALSE
    except psycopg2.Error as e:
        st.error(f"Erro ao verificar primeiro login: {e}")
        return True # Assumir primeiro login em caso de erro
    finally:
        if conn:
            release_connection(conn)

def marcar_primeiro_login_concluido(user_id):
    """Marca o primeiro login como concluído"""
    conn = None
    try:
        conn = get_connection()
        with conn: # Transação atômica
            c = conn.cursor()
            c.execute("UPDATE usuarios SET primeiro_login = FALSE WHERE id=%s", (user_id,))
    except psycopg2.Error as e:
        st.error(f"Erro ao marcar primeiro login: {e}")
    finally:
        if conn:
            release_connection(conn)

# =====================================================
# FUNÇÕES DO BANCO DE DADOS
# =====================================================
def init_db():
    """Inicializa o banco de dados com as tabelas necessárias para PostgreSQL e índices."""
    conn = None
    try:
        conn = get_connection()
        with conn: # Transação atômica para DDL
            c = conn.cursor()
            # Tabela de usuários
            c.execute('''CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                nome TEXT,
                primeiro_nome TEXT,
                matricula TEXT UNIQUE,
                senha_hash TEXT,
                prioridade INTEGER DEFAULT 0,
                horas_usadas INTEGER DEFAULT 0,
                primeiro_login BOOLEAN DEFAULT TRUE,
                data_cadastro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ativo BOOLEAN DEFAULT TRUE
            )''')
            # Índices para usuários
            c.execute("CREATE INDEX IF NOT EXISTS idx_usuarios_primeiro_nome ON usuarios(primeiro_nome);")
            c.execute("CREATE INDEX IF NOT EXISTS idx_usuarios_ativo ON usuarios(ativo);")

            # Tabela de turnos
            c.execute('''CREATE TABLE IF NOT EXISTS turnos (
                id SERIAL PRIMARY KEY,
                data_turno DATE,
                descricao TEXT,
                horas INTEGER,
                reservado_por INTEGER REFERENCES usuarios(id),
                data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ativo BOOLEAN DEFAULT TRUE
            )''')
            # Índices para turnos
            c.execute("CREATE INDEX IF NOT EXISTS idx_turnos_data ON turnos(data_turno);")
            c.execute("CREATE INDEX IF NOT EXISTS idx_turnos_reservado ON turnos(reservado_por);")
            c.execute("CREATE INDEX IF NOT EXISTS idx_turnos_ativo ON turnos(ativo);")

            # Histórico de escalas
            c.execute('''CREATE TABLE IF NOT EXISTS escalas (
                id SERIAL PRIMARY KEY,
                turno_id INTEGER REFERENCES turnos(id),
                data_turno DATE,
                policial_id INTEGER REFERENCES usuarios(id),
                horas_turno INTEGER,
                registrado_em TIMESTAMP,
                rodada INTEGER DEFAULT 1
            )''')
            # Índices para escalas
            c.execute("CREATE INDEX IF NOT EXISTS idx_escalas_policial ON escalas(policial_id);")
            c.execute("CREATE INDEX IF NOT EXISTS idx_escalas_rodada ON escalas(rodada);")
            c.execute("CREATE INDEX IF NOT EXISTS idx_escalas_turno ON escalas(turno_id);")

            # Configurações globais
            c.execute('''CREATE TABLE IF NOT EXISTS config (
                id INTEGER PRIMARY KEY,
                limite_horas INTEGER,
                ciclo_aberto BOOLEAN,
                rodada INTEGER,
                open_selection BOOLEAN DEFAULT FALSE -- NOVO CAMPO
            )''')
            # Controle de bloqueios (concorrência)
            c.execute('''CREATE TABLE IF NOT EXISTS locks (
                id SERIAL PRIMARY KEY,
                turno_id INTEGER UNIQUE REFERENCES turnos(id),
                usuario_id INTEGER REFERENCES usuarios(id),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                operacao TEXT
            )''')
            # Índices para locks
            c.execute("CREATE INDEX IF NOT EXISTS idx_locks_timestamp ON locks(timestamp);")

            # Logs/auditoria
            c.execute('''CREATE TABLE IF NOT EXISTS logs_sistema (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER REFERENCES usuarios(id),
                acao TEXT,
                detalhes TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
            # Índices para logs
            c.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs_sistema(timestamp);")

            # Configuração inicial
            c.execute("""
                INSERT INTO config (id, limite_horas, ciclo_aberto, rodada, open_selection)
                VALUES (1, 48, TRUE, 1, FALSE)
                ON CONFLICT (id) DO NOTHING
            """)
            # Usuário administrador padrão
            senha_admin_hash = bcrypt.hashpw("Itapipoca2025#".encode(), bcrypt.gensalt()).decode()
            c.execute("""
                INSERT INTO usuarios (nome, primeiro_nome, matricula, senha_hash, prioridade, primeiro_login)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (matricula) DO NOTHING
            """, ("Administrador", "admin", "000", senha_admin_hash, 1, False))
    except psycopg2.Error as e:
        st.error(f"⚠️ Erro ao inicializar o banco de dados: {e}")
    finally:
        if conn:
            release_connection(conn)

def log_acao(usuario_id, acao, detalhes=""):
    """Registra uma ação no log do sistema"""
    conn = None
    try:
        conn = get_connection()
        with conn: # Transação atômica
            c = conn.cursor()
            c.execute("INSERT INTO logs_sistema (usuario_id, acao, detalhes, timestamp) VALUES (%s,%s,%s,NOW())",
                      (usuario_id, acao, detalhes))
    except psycopg2.Error as e:
        print(f"Erro ao registrar log: {str(e)}") # Logamos o erro em vez de ignorar
    finally:
        if conn:
            release_connection(conn)

@timed_cache(seconds=30)  # Cache de 30 segundos para configurações
def get_config():
    """Retorna as configurações atuais do sistema com cache"""
    conn = None
    try:
        conn = get_connection()
        c = conn.cursor()
        # Adiciona 'open_selection' na consulta
        c.execute("SELECT limite_horas, ciclo_aberto, rodada, open_selection FROM config WHERE id=1")
        r = c.fetchone()
        # Retorna valor padrão para 'open_selection' se não encontrado
        return r if r else (48, True, 1, False) 
    except psycopg2.Error as e:
        st.error(f"Erro ao obter configurações: {e}")
        return (48, True, 1, False) # Valores padrão em caso de erro
    finally:
        if conn:
            release_connection(conn)

def update_config(limite=None, ciclo=None, rodada=None, open_selection=None): # Adiciona open_selection
    """Atualiza as configurações do sistema"""
    conn = None
    try:
        conn = get_connection()
        with conn: # Transação atômica
            c = conn.cursor()
            if limite is not None:
                c.execute("UPDATE config SET limite_horas=%s WHERE id=1", (int(limite),))
            if ciclo is not None:
                c.execute("UPDATE config SET ciclo_aberto=%s WHERE id=1", (bool(ciclo),)) # PostgreSQL usa TRUE/FALSE
            if rodada is not None:
                c.execute("UPDATE config SET rodada=%s WHERE id=1", (int(rodada),))
            if open_selection is not None: # NOVO: Atualiza open_selection
                c.execute("UPDATE config SET open_selection=%s WHERE id=1", (bool(open_selection),))
        # Invalida o cache da configuração após a atualização
        get_config.clear_cache()
        # Invalida cache de sugestão de horas, pois pode depender do limite
        calcular_sugestao_horas.clear()
    except psycopg2.Error as e:
        st.error(f"Erro ao atualizar configurações: {e}")
    finally:
        if conn:
            release_connection(conn)

def add_user(nome, matricula, prioridade):
    """Adiciona um novo usuário ao sistema"""
    if not nome or not matricula:
        return False, "Nome e matrícula são obrigatórios."
    conn = None
    try:
        conn = get_connection()
        with conn: # Transação atômica
            c = conn.cursor()
            primeiro = nome.split()[0].lower()
            senha_hash = bcrypt.hashpw(matricula.encode(), bcrypt.gensalt()).decode()
            c.execute("INSERT INTO usuarios (nome, primeiro_nome, matricula, senha_hash, prioridade) VALUES (%s,%s,%s,%s,%s)",
                      (nome, primeiro, matricula, senha_hash, int(prioridade)))
        # Invalida o cache de usuários
        listar_usuarios.clear()
        calcular_sugestao_horas.clear()
        return True, "Usuário cadastrado com sucesso."
    except psycopg2.IntegrityError:
        return False, "Matrícula já cadastrada."
    except psycopg2.Error as e:
        st.error(f"Erro ao adicionar usuário: {e}")
        return False, f"Erro ao adicionar usuário: {str(e)}"
    finally:
        if conn:
            release_connection(conn)

def editar_usuario(user_id, nome=None, matricula=None, prioridade=None, ativo=None):
    """Edita os dados de um usuário"""
    conn = None
    try:
        conn = get_connection()
        with conn: # Transação atômica
            c = conn.cursor()
            updates = []
            params = []
            if nome is not None and nome.strip():
                updates.append("nome = %s")
                params.append(nome.strip())
                updates.append("primeiro_nome = %s")
                params.append(nome.strip().split()[0].lower())
            if matricula is not None and matricula.strip():
                updates.append("matricula = %s")
                params.append(matricula.strip())
            if prioridade is not None:
                updates.append("prioridade = %s")
                params.append(int(prioridade))
            if ativo is not None:
                updates.append("ativo = %s")
                params.append(bool(ativo)) # PostgreSQL usa TRUE/FALSE
            if updates:
                params.append(user_id)
                query = f"UPDATE usuarios SET {', '.join(updates)} WHERE id = %s"
                c.execute(query, params)
        # Invalida o cache de usuários
        listar_usuarios.clear()
        calcular_sugestao_horas.clear()
        return True, "Usuário atualizado com sucesso."
    except psycopg2.IntegrityError:
        return False, "Matrícula já existe."
    except psycopg2.Error as e:
        st.error(f"Erro ao atualizar usuário: {e}")
        return False, f"Erro ao atualizar usuário: {str(e)}"
    finally:
        if conn:
            release_connection(conn)

def deletar_usuario(user_id):
    """Deleta um usuário (soft delete - marca como inativo)"""
    conn = None
    try:
        conn = get_connection()
        with conn: # Transação atômica
            c = conn.cursor()
            # Verificar se o usuário tem turnos reservados
            c.execute("SELECT COUNT(*) FROM turnos WHERE reservado_por = %s AND ativo = TRUE", (user_id,))
            turnos_reservados = c.fetchone()[0]
            if turnos_reservados > 0:
                return False, "Não é possível excluir usuário com turnos reservados. Cancele as reservas primeiro."
            # Marcar como inativo ao invés de deletar
            c.execute("UPDATE usuarios SET ativo = FALSE WHERE id = %s", (user_id,))
        # Invalida o cache de usuários e sugestão de horas
        listar_usuarios.clear()
        calcular_sugestao_horas.clear()
        return True, "Usuário removido com sucesso."
    except psycopg2.Error as e:
        st.error(f"Erro ao remover usuário: {e}")
        return False, f"Erro ao remover usuário: {str(e)}"
    finally:
        if conn:
            release_connection(conn)

def alterar_senha_usuario(user_id, senha_atual, nova_senha):
    """Permite ao usuário alterar sua própria senha"""
    conn = None
    try:
        conn = get_connection()
        with conn: # Transação atômica
            c = conn.cursor()
            # Buscar a senha atual
            c.execute("SELECT senha_hash FROM usuarios WHERE id = %s", (user_id,))
            result = c.fetchone()
            if not result:
                return False, "Usuário não encontrado."
            senha_hash_atual = result[0]
            # Verificar senha atual
            if not bcrypt.checkpw(senha_atual.encode(), senha_hash_atual.encode()):
                return False, "Senha atual incorreta."
            # Validar nova senha
            if len(nova_senha) < 4:
                return False, "Nova senha deve ter pelo menos 4 caracteres."
            # Atualizar senha
            nova_senha_hash = bcrypt.hashpw(nova_senha.encode(), bcrypt.gensalt()).decode()
            c.execute("UPDATE usuarios SET senha_hash = %s, primeiro_login = FALSE WHERE id = %s", (nova_senha_hash, user_id))
        return True, "Senha alterada com sucesso!"
    except psycopg2.Error as e:
        st.error(f"Erro ao alterar senha: {e}")
        return False, f"Erro ao alterar senha: {str(e)}"
    finally:
        if conn:
            release_connection(conn)

def get_user_by_login(login):
    """Busca usuário pelo login (primeiro nome)"""
    if not login:
        return None
    conn = None
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT id,nome,primeiro_nome,matricula,senha_hash,prioridade,horas_usadas,primeiro_login,ativo FROM usuarios WHERE primeiro_nome=%s AND ativo=TRUE", (login.lower(),))
        user = c.fetchone()
        return user
    except psycopg2.Error as e:
        st.error(f"Erro ao buscar usuário: {e}")
        return None
    finally:
        if conn:
            release_connection(conn)

@st.cache_data(ttl=300) # Cache para listar usuários
def listar_usuarios(incluir_inativos=False):
    """Lista todos os usuários do sistema"""
    try:
        if incluir_inativos:
            df = pd.read_sql_query("SELECT id,nome,primeiro_nome,matricula,prioridade,horas_usadas,ativo,data_cadastro FROM usuarios ORDER BY nome", db_engine)
        else:
            df = pd.read_sql_query("SELECT id,nome,primeiro_nome,matricula,prioridade,horas_usadas,ativo,data_cadastro FROM usuarios WHERE ativo=TRUE ORDER BY nome", db_engine)
        return df
    except Exception as e:
        st.error(f"Erro ao listar usuários: {e}")
        return pd.DataFrame() # Retorna DataFrame vazio em caso de erro

def add_turno(data_turno_obj, descricao, horas):
    """Adiciona um novo turno ao sistema"""
    iso = display_to_iso(data_turno_obj)
    conn = None
    try:
        conn = get_connection()
        with conn: # Transação atômica
            c = conn.cursor()
            c.execute("INSERT INTO turnos (data_turno, descricao, horas) VALUES (%s,%s,%s)",
                      (iso, descricao, horas))
        # Invalida o cache de turnos e sugestão de horas
        listar_turnos.clear()
        listar_escala_final.clear()
        calcular_sugestao_horas.clear()
    except psycopg2.Error as e:
        st.error(f"Erro ao adicionar turno: {e}")
    finally:
        if conn:
            release_connection(conn)

@st.cache_data(ttl=60) # Cache para listar turnos
def listar_turnos(disponiveis_only=False, incluir_inativos=False):
    """Lista os turnos do sistema com consulta otimizada"""
    try:
        query_parts = []
        if disponiveis_only:
            if incluir_inativos: # Geralmente não faz sentido para 'disponíveis_only'
                query = "SELECT id, data_turno, descricao, horas FROM turnos WHERE reservado_por IS NULL ORDER BY data_turno"
            else:
                query = "SELECT id, data_turno, descricao, horas FROM turnos WHERE reservado_por IS NULL AND ativo=TRUE ORDER BY data_turno"
        else:
            query_parts.append("SELECT t.id, t.data_turno, t.descricao, t.horas, u.nome as reservado_por, t.ativo FROM turnos t")
            query_parts.append("LEFT JOIN usuarios u ON t.reservado_por = u.id")
            
            where_clauses = []
            if not incluir_inativos:
                where_clauses.append("t.ativo=TRUE")
                
            if where_clauses:
                query_parts.append(f"WHERE {' AND '.join(where_clauses)}")
                
            query_parts.append("ORDER BY t.data_turno")
            query = " ".join(query_parts)
            
        df = pd.read_sql_query(query, db_engine)
        
        if not df.empty and 'data_turno' in df.columns:
            df['data_turno'] = df['data_turno'].apply(iso_to_display)
        return df
    except Exception as e:
        st.error(f"Erro ao listar turnos: {e}")
        return pd.DataFrame()

def user_chose_in_round(policial_id, rodada_num):
    """Verifica se o usuário *ainda possui* um turno reservado que foi originalmente escolhido em uma rodada específica."""
    conn = None
    try:
        conn = get_connection()
        c = conn.cursor()
        # Verifica se o policial tem algum turno ATIVO reservado,
        # e se esse turno foi registrado na tabela 'escalas' para a 'rodada_num' específica.
        # Isso garante que apenas reservas *ativas* contem para a regra da rodada.
        c.execute("""
            SELECT COUNT(t.id)
            FROM turnos t
            JOIN escalas e ON t.id = e.turno_id
            WHERE t.reservado_por = %s -- O turno ainda está reservado por este policial
              AND t.ativo = TRUE       -- O turno está ativo
              AND e.policial_id = %s   -- O registro na escala é para este policial
              AND e.rodada = %s        -- E foi feito nesta rodada
        """, (policial_id, policial_id, rodada_num))
        r = c.fetchone()[0]
        return r > 0
    except psycopg2.Error as e:
        st.error(f"Erro ao verificar escolha de rodada: {e}")
        return False
    finally:
        if conn:
            release_connection(conn)

def adquirir_bloqueio(turno_id, usuario_id, operacao):
    """Tenta adquirir um bloqueio para operação em um turno"""
    conn = None
    try:
        conn = get_connection()
        with conn: # Transação atômica
            c = conn.cursor()
            # Limpar bloqueios antigos (mais de 30 segundos)
            c.execute("DELETE FROM locks WHERE timestamp < NOW() - INTERVAL '30 seconds'")
            
            # Verificar se já existe bloqueio
            c.execute("SELECT usuario_id FROM locks WHERE turno_id = %s", (turno_id,))
            result = c.fetchone()
            if result and result[0] != usuario_id:
                return False, "Este turno está sendo modificado por outro usuário. Tente novamente em alguns instantes."
            
            # Adicionar ou atualizar bloqueio (INSERT ... ON CONFLICT para PostgreSQL)
            c.execute("""
                INSERT INTO locks (turno_id, usuario_id, timestamp, operacao)
                VALUES (%s, %s, NOW(), %s)
                ON CONFLICT (turno_id) DO UPDATE
                SET usuario_id = EXCLUDED.usuario_id, timestamp = NOW(), operacao = EXCLUDED.operacao
            """, (turno_id, usuario_id, operacao))
        return True, "Bloqueio adquirido"
    except psycopg2.Error as e:
        st.error(f"Erro ao adquirir bloqueio: {e}")
        return False, f"Erro ao adquirir bloqueio: {str(e)}"
    finally:
        if conn:
            release_connection(conn)

def liberar_bloqueio(turno_id, usuario_id):
    """Libera um bloqueio adquirido"""
    conn = None
    try:
        conn = get_connection()
        with conn: # Transação atômica
            c = conn.cursor()
            c.execute("DELETE FROM locks WHERE turno_id = %s AND usuario_id = %s", (turno_id, usuario_id))
        return True
    except psycopg2.Error as e:
        st.error(f"Erro ao liberar bloqueio para turno {turno_id} por usuário {usuario_id}: {str(e)}")
        return False
    finally:
        if conn:
            release_connection(conn)

def reservar_turno(turno_id, policial_id):
    """Reserva um turno para um policial com controle de concorrência e otimização"""
    # Adquirir bloqueio explícito primeiro
    ok, msg = adquirir_bloqueio(turno_id, policial_id, "reserva")
    if not ok:
        return False, msg
    
    conn = None
    try:
        conn = get_connection()
        
        with conn:  # Inicia transação atômica
            c = conn.cursor()
            
            # 1. Bloqueio explícito no registro do turno e verificação de disponibilidade
            # O SELECT FOR UPDATE garante que ninguém mais possa modificar este turno até o commit
            c.execute("SELECT reservado_por, horas, data_turno FROM turnos WHERE id=%s AND ativo=TRUE FOR UPDATE", (turno_id,))
            r = c.fetchone()
            
            if not r:
                return False, "Turno não encontrado ou inativo."
                
            reservado_por, horas, data_turno = r
            if reservado_por is not None:
                return False, "Turno já foi reservado por outro policial."
                
            # 2. Obter dados do usuário e configurações em uma única consulta
            # Adiciona open_selection na consulta
            c.execute("""
                SELECT u.horas_usadas, c.limite_horas, c.rodada, c.open_selection
                FROM usuarios u, config c
                WHERE u.id=%s AND c.id=1
            """, (policial_id,))
            user_data = c.fetchone()
            
            if not user_data:
                return False, "Usuário não encontrado."
                
            horas_usadas, limite, rodada_atual, open_selection_mode = user_data # Desempacota open_selection
            
            # 3. Verificar limite de horas
            if horas_usadas + horas > limite:
                return False, f"Limite de {limite}h seria ultrapassado."
                
            # 4. Verificar regra da rodada (se aplicável), mas somente se open_selection_mode NÃO estiver ativo
            if not open_selection_mode: # NOVO: Condição para ignorar regras de rodada
                if rodada_atual == 1 and st.session_state['user']['prioridade'] == 0:
                    return False, "Apenas policiais prioritários podem escolher na Rodada 1."
                elif rodada_atual == 2 and user_chose_in_round(policial_id, 1):
                    return False, "Você já possui um turno reservado da rodada prioritária. Não pode escolher na rodada 2."
            
            # 5. Efetuar todas as atualizações
            c.execute("UPDATE turnos SET reservado_por=%s WHERE id=%s", (policial_id, turno_id))
            c.execute("""
                INSERT INTO escalas (turno_id, data_turno, policial_id, horas_turno, registrado_em, rodada) 
                VALUES (%s,%s,%s,%s,NOW(),%s)
            """, (turno_id, data_turno, policial_id, horas, rodada_atual))
            c.execute("UPDATE usuarios SET horas_usadas = horas_usadas + %s WHERE id=%s", (horas, policial_id))
            
            # 6. Log da ação
            c.execute("""
                INSERT INTO logs_sistema (usuario_id, acao, detalhes, timestamp) 
                VALUES (%s, %s, %s, NOW())
            """, (policial_id, "RESERVA_TURNO", f"Turno ID: {turno_id}, Horas: {horas}"))
            
        # Invalida os caches relevantes
        listar_turnos.clear()
        listar_escala_final.clear()
        calcular_sugestao_horas.clear()
        listar_usuarios.clear() # Horas usadas do usuário mudaram
        return True, "Turno reservado com sucesso!"
        
    except psycopg2.Error as e:
        st.error(f"Erro ao reservar turno: {e}")
        return False, f"Erro ao reservar turno: {str(e)}"
    finally:
        if conn:
            release_connection(conn)
        # Garantir que o bloqueio é liberado mesmo em caso de erro
        liberar_bloqueio(turno_id, policial_id)

def cancelar_reserva(turno_id):
    """Cancela a reserva de um turno (função para admin)"""
    admin_id_for_lock = st.session_state['user']['id'] if 'user' in st.session_state else -1
    ok, msg = adquirir_bloqueio(turno_id, admin_id_for_lock, "cancelamento_admin")
    if not ok:
        return False, msg
    conn = None
    try:
        conn = get_connection()
        with conn: # Transação atômica
            c = conn.cursor()
            c.execute("SELECT reservado_por, horas FROM turnos WHERE id=%s FOR UPDATE", (turno_id,)) # Bloqueia a linha
            r = c.fetchone()
            if not r:
                return False, "Turno não encontrado."
            reservado_por, horas = r
            if reservado_por is None:
                return False, "Turno já está livre."
            # Remove a reserva
            c.execute("UPDATE usuarios SET horas_usadas = horas_usadas - %s WHERE id=%s", (horas, reservado_por))
            c.execute("UPDATE turnos SET reservado_por=NULL WHERE id=%s", (turno_id,))
            # Log da ação
            log_acao(admin_id_for_lock, "CANCELAMENTO_TURNO_ADMIN", f"Turno ID: {turno_id}, Horas: {horas}, Policial: {reservado_por}")
        # Invalida os caches relevantes
        listar_turnos.clear()
        listar_escala_final.clear()
        calcular_sugestao_horas.clear()
        listar_usuarios.clear() # Horas usadas do usuário mudaram
        return True, "Reserva cancelada com sucesso."
    except psycopg2.Error as e:
        st.error(f"Erro ao cancelar reserva: {e}")
        return False, f"Erro ao cancelar reserva: {str(e)}"
    finally:
        if conn:
            release_connection(conn)
        liberar_bloqueio(turno_id, admin_id_for_lock)

def cancelar_reserva_pelo_usuario(turno_id, usuario_id):
    """Permite que um usuário cancele sua própria reserva dentro do ciclo"""
    ok, msg = adquirir_bloqueio(turno_id, usuario_id, "cancelamento_usuario")
    if not ok:
        return False, msg
    conn = None
    try:
        conn = get_connection()
        with conn: # Transação atômica
            c = conn.cursor()
            # Verificar se o ciclo está aberto
            _, ciclo, _, _ = get_config() # get_config usa cache, não abre nova conexão, agora retorna 4 valores
            if not ciclo:
                return False, "O ciclo está fechado. Não é possível cancelar reservas."
            # Verificar se o turno pertence ao usuário
            c.execute("SELECT reservado_por, horas FROM turnos WHERE id=%s FOR UPDATE", (turno_id,)) # Bloqueia a linha
            r = c.fetchone()
            if not r or r[0] != usuario_id:
                return False, "Você não pode cancelar este turno, pois não é o proprietário ou o turno não existe."
            # Remove a reserva
            c.execute("UPDATE usuarios SET horas_usadas = horas_usadas - %s WHERE id=%s", (r[1], usuario_id))
            c.execute("UPDATE turnos SET reservado_por=NULL WHERE id=%s", (turno_id,))
            # Log da ação
            log_acao(usuario_id, "CANCELAMENTO_TURNO_PELO_USUARIO", f"Turno ID: {turno_id}, Horas: {r[1]}")
        # Invalida os caches relevantes
        listar_turnos.clear()
        listar_escala_final.clear()
        calcular_sugestao_horas.clear()
        listar_usuarios.clear() # Horas usadas do usuário mudaram
        return True, "Reserva cancelada com sucesso."
    except psycopg2.Error as e:
        st.error(f"Erro ao cancelar reserva: {e}")
        return False, f"Erro ao cancelar reserva: {str(e)}"
    finally:
        if conn:
            release_connection(conn)
        liberar_bloqueio(turno_id, usuario_id)

def excluir_turno(turno_id):
    """Exclui um turno permanentemente do sistema (apenas se não estiver reservado)"""
    admin_id_for_lock = st.session_state['user']['id'] if 'user' in st.session_state else -1
    ok, msg = adquirir_bloqueio(turno_id, admin_id_for_lock, "exclusao_turno")
    if not ok:
        return False, msg
    conn = None
    try:
        conn = get_connection()
        with conn: # Transação atômica
            c = conn.cursor()
            # Verificar se o turno está reservado
            c.execute("SELECT reservado_por FROM turnos WHERE id=%s FOR UPDATE", (turno_id,)) # Bloqueia a linha
            result = c.fetchone()
            if not result:
                return False, "Turno não encontrado."
            if result[0] is not None:
                return False, "Não é possível excluir um turno reservado. Cancele a reserva primeiro."
            # Remover o turno
            c.execute("DELETE FROM turnos WHERE id=%s", (turno_id,))
            # Log da ação
            log_acao(admin_id_for_lock, "EXCLUSAO_TURNO_PERMANENTE", f"Turno ID: {turno_id}")
        # Invalida os caches relevantes
        listar_turnos.clear()
        listar_escala_final.clear()
        calcular_sugestao_horas.clear()
        return True, "Turno excluído com sucesso."
    except psycopg2.Error as e:
        st.error(f"Erro ao excluir turno: {e}")
        return False, f"Erro ao excluir turno: {str(e)}"
    finally:
        if conn:
            release_connection(conn)
        liberar_bloqueio(turno_id, admin_id_for_lock)

@st.cache_data(ttl=60) # Cache para a escala final
def listar_escala_final():
    """Lista a escala final com todos os turnos"""
    try:
        df = pd.read_sql_query("""SELECT t.data_turno, t.descricao, t.horas, u.nome as policial
                                   FROM turnos t LEFT JOIN usuarios u ON t.reservado_por = u.id
                                   WHERE t.ativo=TRUE
                                   ORDER BY t.data_turno""", db_engine)
        if not df.empty and 'data_turno' in df.columns:
            df['data_turno'] = df['data_turno'].apply(iso_to_display)
        return df
    except Exception as e:
        st.error(f"Erro ao listar escala final: {e}")
        return pd.DataFrame()

# =====================================================
# GERAÇÃO DE PDF
# =====================================================
def gerar_pdf_bytes():
    """Gera PDF da escala completa com otimização de performance"""
    try:
        # Garante que os dados estão atualizados
        listar_escala_final.clear() 
        calcular_sugestao_horas.clear()
        listar_usuarios.clear()

        df = listar_escala_final() # Agora vai buscar dados frescos
        
        # Também carregar resumo em uma única consulta
        df_resumo = pd.read_sql_query("""
            SELECT 
                nome, 
                horas_usadas 
            FROM 
                usuarios 
            WHERE 
                horas_usadas > 0 
                AND ativo=TRUE 
            ORDER BY 
                nome
        """, db_engine)
        
        pdf = FPDF()
        pdf.add_page()
        # Cabeçalho
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 15, "ESCALA DE SERVIÇO EXTRA", 0, 1, "C")
        pdf.ln(5)
        # Data de geração
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 8, f"Gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M')}", 0, 1, "R")
        pdf.ln(5)
        # Cabeçalho da tabela
        pdf.set_font("Arial", "B", 11)
        pdf.cell(35, 10, "DATA", 1, 0, "C")
        pdf.cell(80, 10, "DESCRIÇÃO", 1, 0, "C")
        pdf.cell(25, 10, "HORAS", 1, 0, "C")
        pdf.cell(50, 10, "POLICIAL", 1, 1, "C")
        # Dados da tabela
        pdf.set_font("Arial", "", 10)
        for i, row in df.iterrows():
            data = str(row['data_turno'])
            desc = str(row['descricao'])[:35] + "..." if len(str(row['descricao'])) > 35 else str(row['descricao'])
            horas = str(row['horas'])
            policial = str(row['policial']) if pd.notna(row['policial']) else "NÃO ALOCADO"
            pdf.cell(35, 8, data, 1, 0)
            pdf.cell(80, 8, desc, 1, 0)
            pdf.cell(25, 8, horas + "h", 1, 0, "C")
            pdf.cell(50, 8, policial, 1, 1)
        # Resumo por policial
        pdf.ln(10)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "RESUMO DE HORAS POR POLICIAL", 0, 1)
        pdf.set_font("Arial", "", 10)
        for i, row in df_resumo.iterrows():
            pdf.cell(0, 8, f"{row['nome']}: {row['horas_usadas']}h", 0, 1)
        return pdf.output(dest='S').encode('latin-1')
    except Exception as e:
        st.error(f"Erro ao gerar PDF: {e}")
        return None

# =====================================================
# INTERFACE DO USUÁRIO
# =====================================================
def show_change_password_modal():
    """Mostra modal para alteração de senha no primeiro login"""
    with st.form("change_password_form"):
        st.markdown("### 🔐 Primeira vez? Altere sua senha!")
        st.info("Por segurança, recomendamos que você altere sua senha padrão.")
        senha_atual = st.text_input("🔑 Senha atual (sua matrícula)", type="password")
        nova_senha = st.text_input("🆕 Nova senha", type="password")
        confirma_senha = st.text_input("✅ Confirme a nova senha", type="password")
        col1, col2 = st.columns(2)
        with col1:
            alterar = st.form_submit_button("🔄 Alterar Senha", use_container_width=True)
        with col2:
            pular = st.form_submit_button("⏭️ Pular (usar matrícula)", use_container_width=True)
        if alterar:
            if not senha_atual or not nova_senha or not confirma_senha:
                st.error("❌ Preencha todos os campos.")
                return False
            if nova_senha != confirma_senha:
                st.error("❌ As senhas não coincidem.")
                return False
            user_id = st.session_state['user']['id']
            ok, msg = alterar_senha_usuario(user_id, senha_atual, nova_senha)
            if ok:
                st.success(msg)
                marcar_primeiro_login_concluido(user_id)
                st.session_state['primeiro_login_concluido'] = True
                st.rerun()
            else:
                st.error(f"❌ {msg}")
                return False
        elif pular:
            user_id = st.session_state['user']['id']
            marcar_primeiro_login_concluido(user_id)
            st.session_state['primeiro_login_concluido'] = True
            st.info("Você optou por manter a senha padrão. Pode alterar depois no seu perfil.")
            st.rerun()
    return False

def login_page():
    """Página de login do sistema"""
    # Header principal
    st.markdown("""
    <div class="main-header">
        <h1>🚔 Sistema de Escala Policial</h1>
        <p>Gerencie turnos e escalas de forma eficiente</p>
    </div>
    """, unsafe_allow_html=True)
    # Container de login
    with st.container():
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            st.markdown("""
            <div style="background: white; padding: 2rem; border-radius: 15px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
                <h3 style="text-align: center; color: #1e3a8a; margin-bottom: 1.5rem;">🔐 Acesso ao Sistema</h3>
            </div>
            """, unsafe_allow_html=True)
            with st.form("login_form", clear_on_submit=False):
                login = st.text_input("👤 Usuário (primeiro nome)", placeholder="Digite seu primeiro nome")
                senha = st.text_input("🔑 Senha", type="password", placeholder="Digite sua senha")
                col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1])
                with col_btn2:
                    submitted = st.form_submit_button("🚪 ENTRAR", use_container_width=True)
                if submitted:
                    if not login or not senha:
                        st.error("⚠️ Por favor, preencha usuário e senha.")
                        return
                    user_data = get_user_by_login(login)
                    if user_data and bcrypt.checkpw(senha.encode(), user_data[4].encode()):
                        st.session_state['user'] = {
                            "id": user_data[0],
                            "nome": user_data[1],
                            "primeiro": user_data[2],
                            "matricula": user_data[3],
                            "prioridade": user_data[5],
                            "horas_usadas": user_data[6],
                            "primeiro_login": user_data[7] # PostgreSQL retorna bool, Python trata como True/False
                        }
                        # Log do login
                        log_acao(user_data[0], "LOGIN", f"Usuário: {user_data[1]}")
                        st.success(f"✅ Bem-vindo, {user_data[1]}!")
                        st.balloons()
                        st.rerun()
                    else:
                        st.error("❌ Usuário ou senha inválidos.")
    # Informações do sistema
    st.markdown("---")
    col_info1, col_info2 = st.columns(2)
    with col_info1:
        st.markdown("""
        <div class="info-card">
            <h4>📋 Como usar o sistema:</h4>
            <ul>
                <li>Faça login com seu primeiro nome e senha</li>
                <li>No primeiro acesso, pode alterar sua senha</li>
                <li>Escolha turnos disponíveis</li>
                <li>Acompanhe suas horas trabalhadas</li>
                <li>Gere relatórios em PDF</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    with col_info2:
        st.markdown("""
        <div class="success-card">
            <h4> Administradores:</h4>
            <ul>
                <li>Gerencie turnos e usuários</li>
                <li>Configure rodadas e limites</li>
                <li>Acesse relatórios detalhados</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

def show_sugestao_divisao():
    """Exibe sugestão de divisão equilibrada de horas"""
    sugestao = calcular_sugestao_horas()
    st.markdown("""
    <div class="suggestion-card">
        <h4>💡 Sugestão de Divisão Equilibrada</h4>
    </div>
    """, unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        show_metric_card("Total de Horas", f"{sugestao['total_horas_turnos']}h", "em todos os turnos")
    with col2:
        show_metric_card("Total de Policiais", f"{sugestao['total_policiais']}", "ativos no sistema")
    with col3:
        show_metric_card("Horas Disponíveis", f"{sugestao['horas_disponiveis']}h", "ainda não alocadas")
    with col4:
        show_metric_card("Sugestão por Policial", f"{sugestao['sugestao_equilibrada']}h", "para divisão equilibrada")
    if sugestao['total_policiais'] > 0:
        st.markdown(f"""
        <div class="alert-info">
            <strong>📊 Análise:</strong><br>
            • <strong>Divisão equilibrada ideal:</strong> {sugestao['sugestao_equilibrada']}h por policial<br>
            • <strong>Para horas restantes:</strong> {sugestao['sugestao_por_policial']}h por policial<br>
            • <strong>Progresso:</strong> {round((sugestao['horas_alocadas']/sugestao['total_horas_turnos'])*100) if sugestao['total_horas_turnos'] > 0 else 0}% das horas já foram alocadas
        </div>
        """, unsafe_allow_html=True)

def admin_panel():
    """Painel administrativo do sistema"""
    st.markdown("""
    <div class="main-header">
        <h1>🔧 Painel do Administrador</h1>
    </div>
    """, unsafe_allow_html=True)
    limite, ciclo, rodada, open_selection_mode = get_config() # Desempacota open_selection_mode
    # Status do sistema
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        show_metric_card("Limite por Policial", f"{limite}h", "Máximo de horas")
    with col2:
        status_ciclo = "🟢 ABERTO" if ciclo else "🔴 FECHADO"
        show_metric_card("Status do Ciclo", status_ciclo, "Situação atual")
    with col3:
        rodada_text = "1️⃣ PRIORITÁRIOS" if rodada == 1 else "2️⃣ TODOS"
        show_metric_card("Rodada Atual", rodada_text, "Quem pode escolher")
    with col4:
        status_open_selection = "✅ LIGADO" if open_selection_mode else "❌ DESLIGADO" # NOVO: Exibe status
        show_metric_card("Seleção Livre", status_open_selection, "Ignora prioridade/rodada") # NOVO: Métrica de seleção livre
    st.markdown("---")
    # Sugestão de divisão equilibrada
    show_sugestao_divisao()
    st.markdown("---")
    # Análise de capacidade
    st.markdown('<div class="section-header"><h3>📊 Análise de Capacidade</h3></div>', unsafe_allow_html=True)
    df_users = listar_usuarios() # Já filtra ativos por padrão
    
    # Usar uma única consulta para horas não reservadas
    conn = None
    horas_unreserved = 0
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT SUM(horas) FROM turnos WHERE reservado_por IS NULL AND ativo=TRUE")
        unreserved_row = c.fetchone()
        horas_unreserved = int(unreserved_row[0]) if unreserved_row and unreserved_row[0] is not None else 0
    except psycopg2.Error as e:
        st.error(f"Erro ao obter horas não reservadas: {e}")
    finally:
        if conn:
            release_connection(conn)

    if not df_users.empty:
        df_users['horas_restantes'] = df_users['horas_usadas'].apply(lambda u: max(limite - u, 0))
        capacidade_total_restante = int(df_users['horas_restantes'].sum())
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"""
            <div class="info-card">
                <h4>💪 Capacidade Disponível</h4>
                <h2>{capacidade_total_restante}h</h2>
                <p>Total entre todos os policiais</p>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            st.markdown(f"""
            <div class="warning-card">
                <h4>⏰ Turnos Não Alocados</h4>
                <h2>{horas_unreserved}h</h2>
                <p>Precisam ser preenchidos</p>
            </div>
            """, unsafe_allow_html=True)
        if capacidade_total_restante < horas_unreserved:
            st.error("⚠️ **Capacidade insuficiente!** Considere abrir nova rodada ou ajustar limites.")
        else:
            st.success("✅ Capacidade adequada para cobrir todos os turnos.")
    # Tabela de usuários com status
    st.markdown('<div class="section-header"><h3>👥 Status dos Policiais</h3></div>', unsafe_allow_html=True)
    if not df_users.empty:
        conn = None
        participacao_r1 = {}
        try:
            conn = get_connection()
            c = conn.cursor()
            # Consulta para verificar quais policiais têm turnos ativos reservados da rodada 1
            c.execute("""
                SELECT t.reservado_por
                FROM turnos t
                JOIN escalas e ON t.id = e.turno_id
                WHERE t.reservado_por IS NOT NULL AND t.ativo = TRUE AND e.rodada = 1
                GROUP BY t.reservado_por
            """)
            for row in c.fetchall():
                participacao_r1[row[0]] = True
        except psycopg2.Error as e:
            st.error(f"Erro ao carregar participação da rodada 1: {e}")
        finally:
            if conn:
                release_connection(conn)

        df_users['participou_rodada1'] = df_users['id'].apply(lambda uid: participacao_r1.get(uid, False))
        df_users['status'] = df_users.apply(
            lambda r: "🟡 Já participou (R1)" if r['participou_rodada1'] else "🟢 Disponível", axis=1
        )
        df_users['tipo'] = df_users['prioridade'].apply(lambda p: "⭐ Prioritário" if p == 1 else "👤 Regular")
        exibir = df_users[['nome', 'tipo', 'horas_usadas', 'horas_restantes', 'status']].rename(columns={
            'nome': 'Nome',
            'tipo': 'Tipo',
            'horas_usadas': 'Horas Usadas',
            'horas_restantes': 'Horas Restantes',
            'status': 'Status'
        })
        st.dataframe(exibir, use_container_width=True)
    st.markdown("---")
    # Seções principais em abas
    tab1, tab2, tab3, tab4, tab5 = st.tabs(["👤 Usuários", "📅 Turnos", "⚙️ Configurações", "📊 Relatórios", "📋 Logs"])
    with tab1:
        # Sub-abas para gerenciar usuários
        subtab1, subtab2 = st.tabs(["➕ Cadastrar", "✏️ Gerenciar"])
        with subtab1:
            st.markdown('<div class="section-header"><h4>📝 Cadastrar Novo Policial</h4></div>', unsafe_allow_html=True)
            with st.form("cadastro_usuario", clear_on_submit=True):
                col1, col2 = st.columns(2)
                with col1:
                    nome = st.text_input("👤 Nome Completo", placeholder="Ex: João Silva Santos")
                    matricula = st.text_input("🔢 Matrícula", placeholder="Ex: 12345")
                with col2:
                    prioridade = st.checkbox("⭐ Usuário Prioritário", help="Poderá escolher na 1ª rodada")
                    st.write("") # Espaçamento
                    submitted = st.form_submit_button("➕ CADASTRAR USUÁRIO", use_container_width=True)
                if submitted:
                    ok, msg = add_user(nome.strip(), matricula.strip(), int(prioridade))
                    if ok:
                        st.success(f"✅ {msg} **Login:** {nome.split()[0].lower()} | **Senha inicial:** {matricula}")
                        log_acao(st.session_state['user']['id'], "CADASTRO_USUARIO", f"Usuário: {nome}")
                        st.rerun()
                    else:
                        st.error(f"❌ {msg}")
        with subtab2:
            st.markdown('<div class="section-header"><h4>✏️ Gerenciar Usuários</h4></div>', unsafe_allow_html=True)
            # Lista de usuários para edição
            df_all_users = listar_usuarios(incluir_inativos=True)
            if not df_all_users.empty:
                # Filtro para mostrar inativos
                mostrar_inativos = st.checkbox("👁️ Mostrar usuários inativos")
                df_filtered = df_all_users if mostrar_inativos else df_all_users[df_all_users['ativo'] == True]
                for _, user in df_filtered.iterrows():
                    if user['primeiro_nome'] == 'admin': # Não permitir editar admin
                        continue
                    status_text = "🟢 Ativo" if user['ativo'] == True else "🔴 Inativo"
                    tipo_text = "⭐ Prioritário" if user['prioridade'] == 1 else "👤 Regular"
                    with st.expander(f"👤 {user['nome']} - {status_text} - {tipo_text} ({user['horas_usadas']}h)"):
                        col1, col2 = st.columns(2)
                        with col1:
                            with st.form(f"edit_user_{user['id']}"):
                                novo_nome = st.text_input("Nome", value=user['nome'])
                                nova_matricula = st.text_input("Matrícula", value=user['matricula'])
                                nova_prioridade = st.checkbox("Prioritário", value=user['prioridade'] == 1)
                                novo_status = st.checkbox("Usuário Ativo", value=user['ativo'] == True)
                                if st.form_submit_button("💾 Salvar Alterações"):
                                    ok, msg = editar_usuario(
                                        user['id'],
                                        novo_nome,
                                        nova_matricula,
                                        int(nova_prioridade),
                                        bool(novo_status)
                                    )
                                    if ok:
                                        st.success(msg)
                                        log_acao(st.session_state['user']['id'], "EDICAO_USUARIO", f"Usuário: {user['nome']}")
                                        st.rerun()
                                    else:
                                        st.error(msg)
                        with col2:
                            st.write(f"**📅 Cadastrado em:** {user['data_cadastro'].strftime('%Y-%m-%d') if user['data_cadastro'] else 'N/A'}")
                            st.write(f"**⏰ Horas usadas:** {user['horas_usadas']}h")
                            st.write(f"**🆔 ID:** {user['id']}")
                            if user['ativo'] == True and st.button(f"🗑️ Remover Usuário (Inativar)", key=f"del_{user['id']}"):
                                ok, msg = deletar_usuario(user['id'])
                                if ok:
                                    st.success(msg)
                                    log_acao(st.session_state['user']['id'], "REMOCAO_USUARIO", f"Usuário: {user['nome']}")
                                    st.rerun()
                                else:
                                    st.error(msg)
    with tab2:
        st.markdown('<div class="section-header"><h4>📅 Criar Novo Turno</h4></div>', unsafe_allow_html=True)
        with st.form("cadastro_turno", clear_on_submit=True):
            col1, col2, col3 = st.columns(3)
            with col1:
                data_turno = st.date_input("📅 Data do Turno")
            with col2:
                desc = st.text_input("📝 Descrição", placeholder="Ex: Plantão 20:00-02:00")
            with col3:
                horas = st.number_input("⏰ Horas", min_value=1, max_value=24, value=12)
            submitted = st.form_submit_button("➕ ADICIONAR TURNO", use_container_width=True)
            if submitted:
                add_turno(data_turno, desc.strip(), int(horas))
                log_acao(st.session_state['user']['id'], "CRIACAO_TURNO", f"Turno: {desc} - {horas}h")
                st.success("✅ Turno adicionado com sucesso!")
                st.rerun()
        # Lista de turnos
        st.markdown('<div class="section-header"><h4>📋 Gerenciar Turnos</h4></div>', unsafe_allow_html=True)
        df_turnos = listar_turnos(disponiveis_only=False, incluir_inativos=True)
        if df_turnos.empty:
            st.info("ℹ️ Nenhum turno cadastrado ainda.")
        else:
            for _, row in df_turnos.iterrows():
                reservado_por = row['reservado_por'] if pd.notna(row['reservado_por']) else "🟢 DISPONÍVEL"
                status_turno = "🟢 Ativo" if row['ativo'] == True else "🔴 Inativo"
                with st.expander(f"📅 {row['data_turno']} - {row['descricao']} ({row['horas']}h) → {reservado_por} - {status_turno}"):
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        if st.button(f"🚫 Cancelar Reserva", key=f"cancel_{int(row['id'])}"):
                            ok, msg = cancelar_reserva(int(row['id']))
                            if ok:
                                st.success(msg)
                                st.rerun()
                            else:
                                st.error(msg)
                    with col2:
                        # Botão para exclusão permanente
                        if pd.isna(row['reservado_por']): # Só permite excluir se não estiver reservado
                            if st.button(f"🗑️ Excluir Turno (Permanente)", key=f"rem_perm_{int(row['id'])}"):
                                ok, msg = excluir_turno(int(row['id']))
                                if ok:
                                    st.success(msg)
                                    st.rerun()
                                else:
                                    st.error(msg)
                        else:
                            st.info("Para excluir, cancele a reserva primeiro.")
                    with col3:
                        if st.button(f"👮‍♀️ Reservar p/ Admin", key=f"resadm_{int(row['id'])}"):
                            ok, msg = reservar_turno(int(row['id']), 1) # ID 1 é do admin
                            if ok:
                                st.success(msg)
                                st.rerun()
                            else:
                                st.error(msg)
    with tab3:
        st.markdown('<div class="section-header"><h4>⚙️ Configurações do Sistema</h4></div>', unsafe_allow_html=True)
        # Sugestão automática de limite
        sugestao = calcular_sugestao_horas()
        st.markdown(f"""
        <div class="alert-info">
            <strong>💡 Sugestão Automática:</strong> Com base nos turnos cadastrados e número de policiais,
            sugerimos um limite de <strong>{sugestao['sugestao_equilibrada']}h</strong> por policial para divisão equilibrada.
        </div>
        """, unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            novo_limite = st.slider("📊 Limite de Horas por Policial", 10, 100, limite, 1)
            if st.button("💾 Atualizar Limite de Horas"):
                update_config(limite=novo_limite)
                log_acao(st.session_state['user']['id'], "CONFIG_LIMITE", f"Novo limite: {novo_limite}h")
                st.success("✅ Limite atualizado!")
                st.rerun()
            if st.button(f"🎯 Usar Sugestão ({sugestao['sugestao_equilibrada']}h)"):
                update_config(limite=sugestao['sugestao_equilibrada'])
                log_acao(st.session_state['user']['id'], "CONFIG_LIMITE", f"Limite sugerido: {sugestao['sugestao_equilibrada']}h")
                st.success("✅ Limite atualizado com sugestão!")
                st.rerun()
        with col2:
            st.markdown("**🎯 Controle de Rodadas**")
            if st.button("1️⃣ Iniciar Rodada 1 (Prioritários)", use_container_width=True):
                update_config(rodada=1)
                log_acao(st.session_state['user']['id'], "CONFIG_RODADA", "Rodada 1 iniciada")
                st.success("✅ Rodada 1 ativada!")
                st.rerun()
            if st.button("2️⃣ Iniciar Rodada 2 (Não prioritários)", use_container_width=True):
                update_config(rodada=2)
                log_acao(st.session_state['user']['id'], "CONFIG_RODADA", "Rodada 2 iniciada")
                st.success("✅ Rodada 2 ativada!")
                st.rerun()
        st.markdown("---")
        # Controle do ciclo
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**🔄 Controle do Ciclo**")
            if st.button("🟢 Reabrir Ciclo", use_container_width=True):
                update_config(ciclo=1)
                log_acao(st.session_state['user']['id'], "CONFIG_CICLO", "Ciclo reaberto")
                st.success("✅ Ciclo reaberto!")
                st.rerun()
        with col2:
            st.write("") # Espaçamento
            if st.button("🔴 Encerrar Ciclo", use_container_width=True):
                update_config(ciclo=0)
                log_acao(st.session_state['user']['id'], "CONFIG_CICLO", "Ciclo encerrado")
                st.warning("⚠️ Ciclo encerrado!")
                st.rerun()
        st.markdown("---")
        # NOVO: Controle de Seleção Livre
        st.markdown('<div class="section-header"><h4>🔓 Modo de Seleção Livre</h4></div>', unsafe_allow_html=True)
        if open_selection_mode:
            st.success("✅ O modo de seleção livre está ATIVO. As regras de rodada e prioridade estão desativadas.")
            if st.button("❌ Desativar Seleção Livre", use_container_width=True):
                update_config(open_selection=False)
                log_acao(st.session_state['user']['id'], "CONFIG_OPEN_SELECTION", "Seleção livre desativada")
                st.rerun()
        else:
            st.info("ℹ️ O modo de seleção livre está INATIVO. As regras de rodada e prioridade estão ativas.")
            if st.button("✅ Ativar Seleção Livre", use_container_width=True):
                update_config(open_selection=True)
                log_acao(st.session_state['user']['id'], "CONFIG_OPEN_SELECTION", "Seleção livre ativada")
                st.rerun()

    with tab4:
        st.markdown('<div class="section-header"><h4>📊 Relatórios e Exportação</h4></div>', unsafe_allow_html=True)
        if st.button("📄 Gerar PDF da Escala Completa", use_container_width=True):
            pdf_bytes = gerar_pdf_bytes()
            if pdf_bytes:
                st.download_button(
                    "📥 Baixar PDF da Escala",
                    data=pdf_bytes,
                    file_name=f"escala_completa_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            else:
                st.error("Erro ao gerar PDF.")
        # Visualização da escala atual
        st.markdown("**👀 Prévia da Escala Atual:**")
        df_escala = listar_escala_final()
        if not df_escala.empty:
            st.dataframe(df_escala, use_container_width=True)
        else:
            st.info("ℹ️ Nenhum turno cadastrado ainda.")
    with tab5:
        st.markdown('<div class="section-header"><h4>📋 Logs do Sistema</h4></div>', unsafe_allow_html=True)
        try:
            df_logs = pd.read_sql_query("""
                SELECT l.timestamp, u.nome as usuario, l.acao, l.detalhes
                FROM logs_sistema l
                LEFT JOIN usuarios u ON l.usuario_id = u.id
                ORDER BY l.timestamp DESC
                LIMIT 100
            """, db_engine)
            if not df_logs.empty:
                st.dataframe(df_logs, use_container_width=True)
            else:
                st.info("ℹ️ Nenhum log registrado ainda.")
        except Exception as e:
            st.info(f"ℹ️ Erro ao carregar logs: {e}")
        st.markdown('<div class="section-header"><h4>🔍 Monitoramento de Conflitos (Bloqueios Ativos)</h4></div>', unsafe_allow_html=True)
        try:
            df_locks = pd.read_sql_query("""
                SELECT l.turno_id, t.descricao, u.nome as usuario, l.timestamp, l.operacao
                FROM locks l
                JOIN turnos t ON l.turno_id = t.id
                JOIN usuarios u ON l.usuario_id = u.id
                ORDER BY l.timestamp DESC
            """, db_engine)
            if df_locks.empty:
                st.info("Não há operações em andamento no momento.")
            else:
                st.write("Operações em andamento (podem indicar conflitos potenciais):")
                st.dataframe(df_locks, use_container_width=True)
                if st.button("🧹 Limpar Bloqueios Antigos (Forçar)"):
                    conn = None
                    try:
                        conn = get_connection()
                        with conn: # Transação atômica
                            c = conn.cursor()
                            c.execute("DELETE FROM locks WHERE timestamp < NOW() - INTERVAL '30 seconds'")
                        st.success("Bloqueios antigos removidos!")
                        st.rerun()
                    except psycopg2.Error as e:
                        st.error(f"Erro ao limpar bloqueios: {e}")
                    finally:
                        if conn:
                            release_connection(conn)
        except Exception as e:
            st.info(f"ℹ️ Erro ao carregar bloqueios: {e}")

def policial_panel():
    """Painel do policial comum otimizado"""
    user = st.session_state['user']
    user_id = user['id']
    
    # Verificar se é primeiro login
    if user.get('primeiro_login', True) == True and 'primeiro_login_concluido' not in st.session_state:
        st.markdown("""
        <div class="warning-card">
            <h3>🔐 Primeiro Login Detectado!</h3>
            <p>Recomendamos que você altere sua senha para maior segurança.</p>
        </div>
        """, unsafe_allow_html=True)
        show_change_password_modal()
        return
    
    # Obter todos os dados necessários em uma única conexão (ou poucas)
    conn = None
    user_horas = user.get('horas_usadas', 0) # Valor padrão da sessão
    limite, ciclo, rodada, open_selection_mode = get_config() # NOVO: Desempacota open_selection_mode
    
    try:
        conn = get_connection()
        c = conn.cursor()
        
        # 1. Obter horas do usuário (atualizadas)
        c.execute("SELECT horas_usadas FROM usuarios WHERE id=%s", (user_id,))
        user_horas_row = c.fetchone()
        user_horas = user_horas_row[0] if user_horas_row else 0
        st.session_state['user']['horas_usadas'] = user_horas # Atualiza a sessão
        
        # 2. Verificar se o usuário escolheu na rodada 1 (se estamos na rodada 2)
        escolheu_r1 = False
        if rodada == 2:
            # user_chose_in_round agora verifica reservas ATIVAS
            escolheu_r1 = user_chose_in_round(user['id'], 1) 
            
    except psycopg2.Error as e:
        st.error(f"Erro ao carregar dados do usuário: {e}")
        escolheu_r1 = False # Assume falso em caso de erro
    finally:
        if conn:
            release_connection(conn)
            
    # Header personalizado
    st.markdown(f"""
    <div class="main-header">
        <h1> Olá, {user['nome']}!</h1>
        <p>Gerencie seus turnos e acompanhe sua escala</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Métricas do usuário
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        show_metric_card("Horas Trabalhadas", f"{user_horas}h", f"de {limite}h possíveis")
    with col2:
        horas_restantes = max(limite - user_horas, 0)
        show_metric_card("Horas Disponíveis", f"{horas_restantes}h", "ainda pode escolher")
    with col3:
        status_ciclo = "🟢 ABERTO" if ciclo else "🔴 FECHADO"
        show_metric_card("Status", status_ciclo, "para escolhas")
    with col4:
        if open_selection_mode: # NOVO: Mostra status de seleção livre
            show_metric_card("Seleção", "🔓 LIVRE", "Sem restrições de rodada")
        else:
            rodada_text = "1️⃣ PRIORITÁRIOS" if rodada == 1 else "2️⃣ TODOS"
            show_metric_card("Rodada", rodada_text, "atual do sistema")
    # Mostrar sugestão de horas
    sugestao = calcular_sugestao_horas()
    if sugestao['sugestao_equilibrada'] > 0:
        progress = min(user_horas / sugestao['sugestao_equilibrada'], 1.0)
        st.progress(progress, text=f"📊 Progresso: {user_horas}h de {sugestao['sugestao_equilibrada']}h sugeridas para divisão equilibrada")
    st.markdown("---")
    # Verificações de permissão
    pode_escolher = True
    motivo_bloqueio = ""

    if open_selection_mode: # NOVO: Se seleção livre, pode escolher (respeitando limite de horas)
        motivo_bloqueio = "🔓 O modo de seleção livre está ATIVO. Todas as restrições de rodada e prioridade estão desativadas."
        if not ciclo: # Mas o ciclo ainda precisa estar aberto
             pode_escolher = False
             motivo_bloqueio = "🔴 O ciclo de escolhas está encerrado, mesmo no modo de seleção livre."
    else: # Lógica normal de rodadas e prioridade
        if not ciclo:
            pode_escolher = False
            motivo_bloqueio = "🔴 O ciclo de escolhas está encerrado."
        elif rodada == 1 and user['prioridade'] == 0:
            pode_escolher = False
            motivo_bloqueio = "🟡 Apenas policiais prioritários podem escolher na Rodada 1."
        elif rodada == 2 and escolheu_r1: # Usar a variável pré-carregada
            pode_escolher = False
            motivo_bloqueio = "🟡 Você já possui um turno reservado da Rodada 1. Não pode escolher na rodada 2."
    
    # Abas do painel
    tab1, tab2, tab3, tab4 = st.tabs(["🎯 Escolher Turnos", "📋 Minha Escala", "👤 Perfil", "📊 Relatórios"])
    with tab1:
        if not pode_escolher:
            st.markdown(f"""
            <div class="warning-card">
                <h4>⚠️ Escolhas Bloqueadas</h4>
                <p>{motivo_bloqueio}</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown('<div class="section-header"><h4>🎯 Turnos Disponíveis</h4></div><h5 style="margin-top: -1rem;">⚠️Para cancelar uma escolha, vá para a aba "Minha Escala"</h5>', unsafe_allow_html=True)
            df_disp = listar_turnos(disponiveis_only=True)
            if df_disp.empty:
                st.info("ℹ️ Nenhum turno disponível no momento.")
            else:
                for _, row in df_disp.iterrows():
                    with st.container():
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            # Verificar se excederia o limite
                            excederia_limite = (user_horas + row['horas']) > limite
                            excederia_sugestao = (user_horas + row['horas']) > sugestao['sugestao_equilibrada']
                            warning_text = ""
                            if excederia_limite:
                                warning_text = f" ⚠️ (Excederia limite de {limite}h)"
                            elif excederia_sugestao and sugestao['sugestao_equilibrada'] > 0:
                                warning_text = f" ⚠️ (Acima da sugestão de {sugestao['sugestao_equilibrada']}h)"
                            st.write(f"**📅 {row['data_turno']}** - {row['descricao']} (**{row['horas']}h**){warning_text}")
                        with col2:
                            disabled = excederia_limite
                            if st.button(f"✅ Reservar", key=f"res_{int(row['id'])}", use_container_width=True, disabled=disabled):
                                # --- VERIFICAÇÃO DE CONCORRÊNCIA NO FRONTEND ---
                                conn_check = None
                                try:
                                    conn_check = get_connection()
                                    c_check = conn_check.cursor()
                                    c_check.execute("SELECT reservado_por FROM turnos WHERE id=%s AND ativo=TRUE", (int(row['id']),))
                                    check_result = c_check.fetchone()
                                    if check_result and check_result[0] is not None:
                                        st.error("Este turno acabou de ser reservado por outro policial. Atualizando a lista...")
                                        time.sleep(1) # Pequena pausa para o usuário ler
                                        st.rerun()
                                    else:
                                        # Continua com a reserva no backend
                                        ok, msg = reservar_turno(int(row['id']), user['id'])
                                        if ok:
                                            st.success(msg)
                                            st.balloons()
                                            st.rerun()
                                        else:
                                            st.error(msg)
                                finally:
                                    if conn_check:
                                        release_connection(conn_check)
                                # --- FIM DA VERIFICAÇÃO DE CONCORRÊNCIA NO FRONTEND ---
                        st.markdown("---")
    with tab2:
        st.markdown('<div class="section-header"><h4>📋 Meu Histórico de Turnos</h4></div>', unsafe_allow_html=True)
        try:
            # Consulta para o histórico completo, incluindo o status atual do turno
            df_my = pd.read_sql_query(f"""
                SELECT 
                    e.turno_id, 
                    e.data_turno, 
                    t.descricao, 
                    e.horas_turno, 
                    e.registrado_em, 
                    e.rodada,
                    CASE
                        WHEN t.reservado_por = e.policial_id AND t.ativo = TRUE THEN 'Reservado Ativo'
                        WHEN t.reservado_por IS NULL THEN 'Cancelado'
                        ELSE 'Reservado por Outro' -- Caso o turno tenha sido pego por outro (menos comum)
                    END as status_atual_turno
                FROM escalas e 
                LEFT JOIN turnos t ON e.turno_id = t.id
                WHERE e.policial_id={user['id']}
                ORDER BY e.registrado_em DESC
            """, db_engine)
        except Exception as e:
            st.error(f"Erro ao carregar histórico de turnos: {e}")
            df_my = pd.DataFrame()
        if df_my.empty:
            st.info("ℹ️ Você ainda não possui turnos registrados.")
        else:
            st.markdown('#### 🔄 Meus Turnos Atuais')
            # Verificar se o ciclo está aberto
            _, ciclo_aberto, _, _ = get_config() # NOVO: Desempacota open_selection_mode
            # Filtrar turnos que ainda estão ativos e reservados por este usuário
            try:
                df_my_active_turnos = pd.read_sql_query(f"""
                    SELECT t.id, t.data_turno, t.descricao, t.horas
                    FROM turnos t
                    WHERE t.reservado_por = {user['id']} AND t.ativo = TRUE
                    ORDER BY t.data_turno
                """, db_engine)
            except Exception as e:
                st.error(f"Erro ao carregar turnos ativos: {e}")
                df_my_active_turnos = pd.DataFrame()
            if not df_my_active_turnos.empty:
                st.write("Você pode cancelar turnos que você reservou, se o ciclo estiver aberto.")
                for _, row in df_my_active_turnos.iterrows():
                    with st.container():
                        col1, col2 = st.columns([3, 1])
                        with col1:
                            st.write(f"**📅 {iso_to_display(row['data_turno'])}** - {row['descricao']} (**{row['horas']}h**)")
                        with col2:
                            if ciclo_aberto:
                                if st.button("❌ Cancelar", key=f"cancel_my_{row['id']}", use_container_width=True):
                                    ok, msg = cancelar_reserva_pelo_usuario(int(row['id']), user['id'])
                                    if ok:
                                        st.success(msg)
                                        st.rerun()
                                    else:
                                        st.error(msg)
                            else:
                                st.info("🔒 Ciclo fechado. Não é possível cancelar.")
                        st.markdown("---")
            else:
                st.info("Você não tem turnos ativos reservados no momento.")
            st.markdown('#### 📚 Histórico Completo de Reservas (inclui cancelados)')
            # Formatação das datas para exibição
            df_my['data_turno'] = df_my['data_turno'].apply(iso_to_display)
            if 'rodada' in df_my.columns:
                df_my['rodada'] = df_my['rodada'].apply(lambda r: f"Rodada {r}")
            else:
                df_my['rodada'] = "Rodada 1" # Fallback se a coluna não existir
            df_display = df_my[['data_turno', 'descricao', 'horas_turno', 'registrado_em', 'rodada', 'status_atual_turno']].rename(columns={
                'data_turno': 'Data',
                'descricao': 'Descrição',
                'horas_turno': 'Horas',
                'registrado_em': 'Registrado em',
                'rodada': 'Rodada',
                'status_atual_turno': 'Status Atual'
            })
            st.dataframe(df_display, use_container_width=True)
    with tab3:
        st.markdown('<div class="section-header"><h4>👤 Meu Perfil</h4></div>', unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"""
            <div class="info-card">
                <h4>📋 Informações Pessoais</h4>
                <p><strong>Nome:</strong> {user['nome']}</p>
                <p><strong>Matrícula:</strong> {user['matricula']}</p>
                <p><strong>Tipo:</strong> {'⭐ Prioritário' if user['prioridade'] == 1 else '👤 Regular'}</p>
                <p><strong>Horas Trabalhadas:</strong> {user_horas}h</p>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            st.markdown('<div class="section-header"><h4>🔑 Alterar Senha</h4></div>', unsafe_allow_html=True)
            with st.form("alterar_senha"):
                senha_atual = st.text_input("Senha Atual", type="password")
                nova_senha = st.text_input("Nova Senha", type="password")
                confirma_senha = st.text_input("Confirme Nova Senha", type="password")
                if st.form_submit_button("🔄 Alterar Senha", use_container_width=True):
                    if not senha_atual or not nova_senha or not confirma_senha:
                        st.error("❌ Preencha todos os campos.")
                    elif nova_senha != confirma_senha:
                        st.error("❌ As senhas não coincidem.")
                    else:
                        ok, msg = alterar_senha_usuario(user['id'], senha_atual, nova_senha)
                        if ok:
                            st.success(msg)
                            log_acao(user['id'], "ALTERACAO_SENHA", "Senha alterada pelo usuário")
                        else:
                            st.error(f"❌ {msg}")
    with tab4:
        st.markdown('<div class="section-header"><h4>📊 Meus Relatórios</h4></div>', unsafe_allow_html=True)
        if st.button("📄 Gerar PDF dos Meus Turnos Ativos", use_container_width=True):
            try:
                # --- ALTERAÇÃO AQUI: Consulta apenas turnos ATIVOS e reservados pelo usuário ---
                df_personal = pd.read_sql_query(f"""
                    SELECT t.data_turno, t.descricao, t.horas
                    FROM turnos t
                    WHERE t.reservado_por = {user['id']} AND t.ativo = TRUE
                    ORDER BY t.data_turno
                """, db_engine)
            except Exception as e:
                st.error(f"Erro ao carregar dados para relatório pessoal: {e}")
                df_personal = pd.DataFrame()
            # Gerar PDF personalizado
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", "B", 16)
            pdf.cell(0, 15, f"ESCALA INDIVIDUAL - {user['nome'].upper()}", 0, 1, "C")
            pdf.ln(5)
            pdf.set_font("Arial", "", 11)
            pdf.cell(0, 8, f"Matrícula: {user['matricula']}", 0, 1)
            pdf.cell(0, 8, f"Total de horas ativas: {user_horas}h", 0, 1) # Reflete horas_usadas
            pdf.cell(0, 8, f"Gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M')}", 0, 1)
            pdf.ln(5)
            if df_personal.empty:
                pdf.cell(0, 10, "Nenhum turno ativo registrado.", 0, 1)
            else:
                # Cabeçalho da tabela
                pdf.set_font("Arial", "B", 10)
                pdf.cell(35, 8, "DATA", 1, 0, "C")
                pdf.cell(115, 8, "DESCRIÇÃO", 1, 0, "C") # Aumentado para 115
                pdf.cell(25, 8, "HORAS", 1, 1, "C") # 1, 1 para quebrar linha
                # Dados
                pdf.set_font("Arial", "", 9)
                for _, row in df_personal.iterrows():
                    data = iso_to_display(row['data_turno'])
                    # Limitar descrição a 60 caracteres (ajustado para caber no novo layout)
                    desc = (
                        str(row['descricao'])[:60] + "..."
                        if len(str(row['descricao'])) > 60
                        else str(row['descricao'])
                    )
                    horas = str(row['horas'])
                    # 'registrado_em' não é mais relevante para turnos ativos nesta visualização
                    # pdf.cell(40, 8, registrado, 1, 1)
                    # Colunas da tabela
                    pdf.cell(35, 8, data, 1, 0)
                    pdf.cell(115, 8, desc, 1, 0)
                    pdf.cell(25, 8, horas + "h", 1, 1, "C") # 1, 1 para quebrar linha
            pdf_bytes = pdf.output(dest='S').encode('latin-1')
            st.download_button(
                "📥 Baixar Meu PDF",
                data=pdf_bytes,
                file_name=f"escala_{user['primeiro']}_{datetime.now().strftime('%Y%m%d')}.pdf",
                mime="application/pdf",
                use_container_width=True
            )
# =====================================================
# APLICAÇÃO PRINCIPAL
# =====================================================
def main():
    """Função principal da aplicação"""
    # Inicializar o pool de conexões e o banco de dados
    if initialize_connection_pool():
        init_db()
    else:
        st.error("Falha ao inicializar o sistema. Verifique as configurações do banco de dados.")
        st.stop() # Interrompe a execução se o pool falhar

    # Sidebar
    st.sidebar.markdown("""
    <div style="text-align: center; padding: 1rem;">
        <h2>🚔 Sistema de Escala</h2>
        <p style="font-size: 0.8rem; color: #666;">v2.1 </p>
    </div>
    """, unsafe_allow_html=True)
    if 'user' not in st.session_state:
        st.sidebar.info("👤 Faça login para acessar o sistema")
        login_page()
    else:
        user = st.session_state['user']
        # Informações do usuário na sidebar
        st.sidebar.markdown(f"""
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                                 color: white; padding: 1rem; border-radius: 10px; margin-bottom: 1rem;">
            <h4 style="margin: 0;">👤 {user['nome']}</h4>
            <p style="margin: 0; font-size: 0.8rem;">Matrícula: {user['matricula']}</p>
            <p style="margin: 0; font-size: 0.8rem;">
                {'⭐ Prioritário' if user['prioridade'] == 1 else '👤 Regular'}
            </p>
            <p style="margin: 0; font-size: 0.8rem;">💼 {user['horas_usadas']}h trabalhadas</p>
        </div>
        """, unsafe_allow_html=True)
        # Menu de navegação
        if user['primeiro'] == 'admin':
            opcoes = ["🔧 Painel Admin", "👁️ Visualizar Escala"]
        else:
            opcoes = ["🏠 Meu Painel", "👁️ Visualizar Escala"]
        page = st.sidebar.selectbox("📋 Navegação", opcoes)
        # Renderização das páginas
        if page == "🔧 Painel Admin":
            admin_panel()
        elif page == "🏠 Meu Painel":
            policial_panel()
        else: # Visualizar Escala
            st.markdown("""
            <div class="main-header">
                <h1>👁️ Escala Atual</h1>
                <p>Visualização completa dos turnos e alocações</p>
            </div>
            """, unsafe_allow_html=True)
            df = listar_escala_final()
            if df.empty:
                st.info("ℹ️ Nenhum turno cadastrado ainda.")
            else:
                # Mostrar métricas da escala
                total_horas = df['horas'].sum()
                turnos_alocados = df['policial'].notna().sum()
                total_turnos = len(df)
                col1, col2, col3 = st.columns(3)
                with col1:
                    show_metric_card("Total de Horas", f"{total_horas}h", "em todos os turnos")
                with col2:
                    show_metric_card("Turnos Alocados", f"{turnos_alocados}/{total_turnos}", "turnos preenchidos")
                with col3:
                    progresso = round((turnos_alocados/total_turnos)*100) if total_turnos > 0 else 0
                    show_metric_card("Progresso", f"{progresso}%", "da escala completa")
                st.markdown("---")
                # Renomear colunas para melhor apresentação
                df_display = df.rename(columns={
                    'data_turno': 'Data',
                    'descricao': 'Descrição',
                    'horas': 'Horas',
                    'policial': 'Policial Alocado'
                })
                # Preencher valores nulos
                df_display['Policial Alocado'] = df_display['Policial Alocado'].fillna('🔴 NÃO ALOCADO')
                st.dataframe(df_display, use_container_width=True)
                # Botão para download
                if st.button("📄 Baixar PDF da Escala", use_container_width=True):
                    pdf_bytes = gerar_pdf_bytes()
                    if pdf_bytes:
                        st.download_button(
                            "📥 Download PDF",
                            data=pdf_bytes,
                            file_name=f"escala_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                            mime="application/pdf",
                            use_container_width=True
                        )
                    else:
                        st.error("Erro ao gerar PDF.")
        # Botão de logout na sidebar
        st.sidebar.markdown("---")
        if st.sidebar.button("🚪 Sair", use_container_width=True):
            # Log do logout
            log_acao(user['id'], "LOGOUT", f"Usuário: {user['nome']}")
            st.session_state.pop('user', None)
            st.rerun()
        # Informações do sistema na sidebar
        st.sidebar.markdown("---")
        st.sidebar.markdown("""
        <div style="font-size: 0.7rem; color: #666; text-align: center;">
            Sistema de Escalas Policiais<br>
            Versão 2.1 - <br>
            By Robson Oliveira
        </div>
        """, unsafe_allow_html=True)
# Executar aplicação
if __name__ == "__main__":
    main()
