import pandas as pd
import psycopg2
import bcrypt
import re

# -------------------------------------------------------------------
# CONFIGURAÇÕES DE ACESSO AO BANCO
# -------------------------------------------------------------------
DATABASE_URL = (
    "postgresql://postgres.vdeepsydnybiabmtnjwn:"
    "R@bson1080#@aws-1-sa-east-1.pooler.supabase.com:6543/postgres"
)

EXCEL_FILE = "policiais.xlsx"   # coloque o caminho correto
SHEET_NAME = 0                  # 0 = primeira aba (não precisa nome exato)

def importar_policiais():
    # Lê a planilha, garantindo nomes de colunas consistentes
    df = pd.read_excel(EXCEL_FILE, sheet_name=SHEET_NAME)
    df.columns = [c.strip().upper() for c in df.columns]

    conn = None
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()

        for _, row in df.iterrows():
            nome = str(row["NOME"]).strip()
            matricula_raw = str(row["MATRÍCULA"]).strip()
            preferencia = str(row["PREFERENCIA"]).strip().upper()

            # Normaliza matrícula: remove espaços e caracteres não numéricos/letra final
            matricula = re.sub(r"\s+", "", matricula_raw)

            # Extrai primeiro nome (antes do primeiro espaço)
            primeiro_nome = nome.split()[0].capitalize()

            # Converte preferencia em prioridade (SIM = 1, caso contrário 0)
            prioridade = 1 if preferencia == "SIM" else 0

            # Senha inicial = matrícula
            senha_hash = bcrypt.hashpw(matricula.encode(), bcrypt.gensalt()).decode()

            cur.execute("""
                INSERT INTO usuarios (nome, primeiro_nome, matricula, senha_hash, prioridade, primeiro_login)
                VALUES (%s, %s, %s, %s, %s, TRUE)
                ON CONFLICT (matricula) DO NOTHING
            """, (nome, primeiro_nome, matricula, senha_hash, prioridade))

        conn.commit()
        print(f"✅ {len(df)} policiais processados com sucesso.")

    except Exception as e:
        if conn:
            conn.rollback()
        print("❌ Erro na importação:", e)

    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    importar_policiais()
