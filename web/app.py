import os
import re
import hashlib
import secrets
import subprocess
import ipaddress
import logging
import requests
import psycopg2
import psycopg2.extras
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, session,
)
from werkzeug.security import generate_password_hash, check_password_hash

log = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

try:
    import librouteros
    MIKROTIK_AVAILABLE = True
except ImportError:
    MIKROTIK_AVAILABLE = False

# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def get_db():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "postgres"),
        dbname=os.environ.get("DB_NAME", "radius"),
        user=os.environ.get("DB_USER", "radius"),
        password=os.environ.get("DB_PASS", "radiuspassword"),
    )


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("usuario_id"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key", "")
        if not key:
            return jsonify({"error": "Header X-API-Key obrigatório"}), 401
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        conn = get_db()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id FROM api_keys WHERE key_hash = %s AND ativo = TRUE",
                (key_hash,),
            )
            found = cur.fetchone()
            if found:
                cur.execute(
                    "UPDATE api_keys SET ultimo_uso = NOW() WHERE id = %s",
                    (found["id"],),
                )
                conn.commit()
        conn.close()
        if not found:
            return jsonify({"error": "API Key inválida ou inativa"}), 401
        return f(*args, **kwargs)
    return decorated


def create_default_admin():
    """Cria usuário admin padrão se a tabela de usuários estiver vazia."""
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM usuarios")
            count = cur.fetchone()[0]
            if count == 0:
                pwd_hash = generate_password_hash("admin123")
                cur.execute(
                    "INSERT INTO usuarios (username, senha_hash, role) VALUES (%s, %s, %s)",
                    ("admin", pwd_hash, "admin"),
                )
                conn.commit()
                log.info("Usuário admin padrão criado (senha: admin123)")
        conn.close()
    except Exception as e:
        log.warning("Não foi possível criar usuário padrão: %s", e)


# ---------------------------------------------------------------------------
# SGP helpers
# ---------------------------------------------------------------------------

SGP_URL = os.environ.get("SGP_URL", "https://linknetam.sgp.net.br/api/ura/consultacliente/")
SGP_TOKEN = os.environ.get("SGP_TOKEN", "")
SGP_APP = os.environ.get("SGP_APP", "APP")


def consultar_sgp(cpf: str) -> dict | None:
    """Consulta o SGP e retorna o primeiro contrato encontrado ou None."""
    try:
        resp = requests.post(
            SGP_URL,
            data={"token": SGP_TOKEN, "app": SGP_APP, "cpfcnpj": cpf},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        contratos = data.get("contratos", [])
        if contratos:
            return contratos[0]
    except requests.RequestException:
        pass
    return None


def status_from_sgp(contrato: dict) -> str:
    display = contrato.get("contratoStatusDisplay", "").lower()
    return "ativo" if display == "ativo" else "suspenso"


# ---------------------------------------------------------------------------
# RADIUS helpers
# ---------------------------------------------------------------------------

def upsert_radius_user(conn, login: str, status: str, down: int, up: int, ip: str = ""):
    with conn.cursor() as cur:
        cur.execute("DELETE FROM radcheck WHERE username = %s", (login,))
        cur.execute("DELETE FROM radreply WHERE username = %s", (login,))

        if status == "ativo":
            cur.execute(
                "INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, %s, %s, %s)",
                (login, "Cleartext-Password", ":=", "123"),
            )
            rate = f"{up}M/{down}M"
            cur.execute(
                "INSERT INTO radreply (username, attribute, op, value) VALUES (%s, %s, %s, %s)",
                (login, "Mikrotik-Rate-Limit", ":=", rate),
            )
            if ip:
                cur.execute(
                    "INSERT INTO radreply (username, attribute, op, value) VALUES (%s, %s, %s, %s)",
                    (login, "Framed-IP-Address", ":=", ip),
                )
        else:
            cur.execute(
                "INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, %s, %s, %s)",
                (login, "Auth-Type", ":=", "Reject"),
            )
    conn.commit()


def remove_radius_user(conn, login: str):
    with conn.cursor() as cur:
        cur.execute("DELETE FROM radcheck WHERE username = %s", (login,))
        cur.execute("DELETE FROM radreply WHERE username = %s", (login,))
    conn.commit()


def disconnect_user(conn, username: str):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT ra.acctsessionid, ra.nasipaddress, n.secret
            FROM radacct ra
            JOIN nas n ON host(ra.nasipaddress) = n.nasname
            WHERE ra.username = %s AND ra.acctstoptime IS NULL
            LIMIT 1
        """, (username,))
        session_row = cur.fetchone()

    if not session_row:
        return False

    nas_ip = str(session_row["nasipaddress"])
    secret = session_row["secret"]
    session_id = session_row["acctsessionid"]

    try:
        cmd = ["radclient", "-x", f"{nas_ip}:3799", "disconnect", secret]
        input_data = f"Acct-Session-Id = {session_id}\nUser-Name = {username}\n"
        result = subprocess.run(cmd, input=input_data, capture_output=True,
                                text=True, timeout=5)
        return result.returncode == 0
    except Exception as e:
        log.warning("Falha ao desconectar %s: %s", username, e)
        return False


def check_ip_unique(conn, ip: str, exclude_id: int = 0) -> bool:
    if not ip:
        return True
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM clientes WHERE ip = %s AND id != %s", (ip, exclude_id))
        return cur.fetchone() is None


def check_pppoe_login_unique(conn, pppoe_login: str, exclude_id: int = 0) -> bool:
    if not pppoe_login:
        return True
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM clientes WHERE pppoe_login = %s AND id != %s",
            (pppoe_login, exclude_id),
        )
        return cur.fetchone() is None


def alocar_ip_do_pool(conn, pool_id: int) -> str | None:
    """Retorna o próximo IP livre do pool, ou None se esgotado."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM pools WHERE id = %s", (pool_id,))
        pool = cur.fetchone()
    if not pool:
        return None
    try:
        start = ipaddress.ip_address(pool["range_inicio"])
        end = ipaddress.ip_address(pool["range_fim"])
    except ValueError:
        return None

    with conn.cursor() as cur:
        cur.execute("SELECT ip FROM clientes WHERE ip IS NOT NULL AND ip != ''")
        used_ips = {row[0] for row in cur.fetchall()}

    current = start
    while current <= end:
        ip_str = str(current)
        if ip_str not in used_ips:
            return ip_str
        current += 1
    return None


def pool_stats(conn, pool_id: int) -> dict:
    """Retorna estatísticas de uso de IPs de um pool."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM pools WHERE id = %s", (pool_id,))
        pool = cur.fetchone()
    if not pool:
        return {"total": 0, "usados": 0, "livres": 0, "percentual": 0}
    try:
        start = ipaddress.ip_address(pool["range_inicio"])
        end = ipaddress.ip_address(pool["range_fim"])
        total = int(end) - int(start) + 1
    except ValueError:
        return {"total": 0, "usados": 0, "livres": 0, "percentual": 0}

    with conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM clientes WHERE ip IS NOT NULL AND ip != '' AND pool_id = %s",
            (pool_id,),
        )
        usados = cur.fetchone()[0]

    livres = max(0, total - usados)
    percentual = round((usados / total) * 100, 1) if total > 0 else 0
    return {"total": total, "usados": usados, "livres": livres, "percentual": percentual}


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def page_not_found(_e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(_e):
    return render_template("500.html"), 500


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("usuario_id"):
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        senha = request.form.get("senha", "")
        next_url = request.form.get("next", "")

        conn = get_db()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM usuarios WHERE username = %s AND ativo = TRUE",
                (username,),
            )
            usuario = cur.fetchone()
            if usuario and check_password_hash(usuario["senha_hash"], senha):
                cur.execute(
                    "UPDATE usuarios SET ultimo_acesso = NOW() WHERE id = %s",
                    (usuario["id"],),
                )
                conn.commit()
                conn.close()
                session["usuario_id"] = usuario["id"]
                session["usuario_username"] = usuario["username"]
                session["usuario_role"] = usuario["role"]
                return redirect(next_url or url_for("index"))
            conn.close()
        flash("Usuário ou senha inválidos.", "danger")

    next_url = request.args.get("next", "")
    return render_template("login.html", next=next_url)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def index():
    pagina = int(request.args.get("pagina", 1))
    por_pagina = int(request.args.get("por_pagina", 50))
    busca = request.args.get("busca", "").strip()
    filtro_status = request.args.get("status", "").strip()

    offset = (pagina - 1) * por_pagina

    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        # Sessões ativas
        cur.execute("SELECT username FROM radacct WHERE acctstoptime IS NULL")
        online_users = {row["username"] for row in cur.fetchall()}

        # Query base com filtros
        where_clauses = []
        params = []

        if busca:
            where_clauses.append(
                "(c.nome ILIKE %s OR c.cpf ILIKE %s OR c.pppoe_login ILIKE %s OR c.ip ILIKE %s)"
            )
            like = f"%{busca}%"
            params.extend([like, like, like, like])

        if filtro_status in ("ativo", "suspenso", "pendente"):
            where_clauses.append("c.status = %s")
            params.append(filtro_status)
        elif filtro_status == "online":
            if online_users:
                placeholders = ",".join(["%s"] * len(online_users))
                where_clauses.append(f"c.pppoe_login IN ({placeholders})")
                params.extend(list(online_users))
            else:
                where_clauses.append("FALSE")
        elif filtro_status == "offline":
            if online_users:
                placeholders = ",".join(["%s"] * len(online_users))
                where_clauses.append(f"(c.pppoe_login IS NULL OR c.pppoe_login NOT IN ({placeholders}))")
                params.extend(list(online_users))

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        # Total para paginação
        cur.execute(
            f"SELECT COUNT(*) FROM clientes c {where_sql}",
            params,
        )
        total_filtrado = cur.fetchone()["count"]

        # Clientes paginados
        cur.execute(
            f"""SELECT c.*, p.nome AS plano_nome, po.nome AS pool_nome
                FROM clientes c
                LEFT JOIN planos p ON c.plano_id = p.id
                LEFT JOIN pools po ON c.pool_id = po.id
                {where_sql}
                ORDER BY c.criado_em DESC
                LIMIT %s OFFSET %s""",
            params + [por_pagina, offset],
        )
        clientes = cur.fetchall()

        # Stats gerais
        cur.execute("SELECT COUNT(*) AS total FROM clientes")
        total_clientes = cur.fetchone()["total"]
        cur.execute("SELECT COUNT(*) AS total FROM clientes WHERE status = 'ativo'")
        total_ativos = cur.fetchone()["total"]
        cur.execute("SELECT COUNT(*) AS total FROM clientes WHERE status = 'suspenso'")
        total_suspensos = cur.fetchone()["total"]
        cur.execute("SELECT COUNT(*) AS total FROM planos")
        total_planos = cur.fetchone()["total"]
        cur.execute("SELECT COUNT(*) AS total FROM pools")
        total_pools = cur.fetchone()["total"]
        cur.execute("SELECT COUNT(*) AS total FROM nas")
        total_nas = cur.fetchone()["total"]

    conn.close()

    total_online = 0
    for c in clientes:
        c["online"] = bool(c["pppoe_login"] and c["pppoe_login"] in online_users)
        if c["online"]:
            total_online += 1

    total_paginas = max(1, (total_filtrado + por_pagina - 1) // por_pagina)

    stats = {
        "total_clientes": total_clientes,
        "total_ativos": total_ativos,
        "total_suspensos": total_suspensos,
        "total_online": len(online_users),
        "total_offline": total_clientes - len(online_users),
        "total_planos": total_planos,
        "total_pools": total_pools,
        "total_nas": total_nas,
    }
    paginacao = {
        "pagina": pagina,
        "por_pagina": por_pagina,
        "total": total_filtrado,
        "total_paginas": total_paginas,
        "busca": busca,
        "status": filtro_status,
    }
    return render_template("index.html", clientes=clientes, stats=stats, paginacao=paginacao)


# ---------------------------------------------------------------------------
# Clientes CRUD
# ---------------------------------------------------------------------------

@app.route("/cliente/novo", methods=["GET", "POST"])
@login_required
def novo_cliente():
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM planos ORDER BY nome")
        planos = cur.fetchall()
        cur.execute("SELECT * FROM pools ORDER BY nome")
        pools = cur.fetchall()

    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        cpf = re.sub(r"\D", "", request.form.get("cpf", ""))
        ip = request.form.get("ip", "").strip()
        plano_id = request.form.get("plano_id", "").strip()
        pool_id = request.form.get("pool_id", "").strip()

        if not nome or not cpf or not plano_id:
            flash("Nome, CPF e Plano são obrigatórios.", "danger")
            conn.close()
            return render_template("form_cliente.html", cliente=None, planos=planos, pools=pools)

        if len(cpf) != 11:
            flash(f"CPF inválido: deve ter 11 dígitos (recebido {len(cpf)}).", "danger")
            conn.close()
            return render_template("form_cliente.html", cliente=None, planos=planos, pools=pools)

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM planos WHERE id = %s", (plano_id,))
            plano_obj = cur.fetchone()

        if not plano_obj:
            flash("Plano selecionado não encontrado.", "danger")
            conn.close()
            return render_template("form_cliente.html", cliente=None, planos=planos, pools=pools)

        plano_nome = plano_obj["nome"]
        vel_down = plano_obj["velocidade_down"]
        vel_up = plano_obj["velocidade_up"]
        pool_id_val = int(pool_id) if pool_id else None

        # Auto-alocar IP do pool se IP não foi informado
        if not ip and pool_id_val:
            ip = alocar_ip_do_pool(conn, pool_id_val) or ""

        contrato = consultar_sgp(cpf)
        pppoe_login = None
        status = "pendente"

        if contrato:
            pppoe_login = contrato.get("contratoCentralLogin")
            status = status_from_sgp(contrato)
            if not ip:
                ip = contrato.get("servico_ip", "")
        else:
            flash("Aviso: não foi possível consultar o SGP. Cliente salvo como pendente.", "warning")

        if not check_ip_unique(conn, ip):
            flash(f"O IP {ip} já está em uso por outro cliente.", "danger")
            conn.close()
            return render_template("form_cliente.html", cliente=None, planos=planos, pools=pools)

        if pppoe_login and not check_pppoe_login_unique(conn, pppoe_login):
            flash(f"O login PPPoE '{pppoe_login}' já está cadastrado para outro cliente.", "danger")
            conn.close()
            return render_template("form_cliente.html", cliente=None, planos=planos, pools=pools)

        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO clientes (nome, cpf, ip, plano, velocidade_down, velocidade_up,
                       plano_id, pool_id, pppoe_login, status, ultimo_sync_em)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())""",
                    (nome, cpf, ip, plano_nome, vel_down, vel_up,
                     int(plano_id), pool_id_val, pppoe_login, status),
                )
            conn.commit()

            if pppoe_login:
                upsert_radius_user(conn, pppoe_login, status, vel_down, vel_up, ip)

            flash(f"Cliente cadastrado com sucesso! Status SGP: {status}", "success")
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            flash("Já existe um cliente com este CPF.", "danger")
        finally:
            conn.close()

        return redirect(url_for("index"))

    conn.close()
    return render_template("form_cliente.html", cliente=None, planos=planos, pools=pools)


@app.route("/cliente/<int:cliente_id>/editar", methods=["GET", "POST"])
@login_required
def editar_cliente(cliente_id):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM clientes WHERE id = %s", (cliente_id,))
        cliente = cur.fetchone()
        cur.execute("SELECT * FROM planos ORDER BY nome")
        planos = cur.fetchall()
        cur.execute("SELECT * FROM pools ORDER BY nome")
        pools = cur.fetchall()

    if not cliente:
        flash("Cliente não encontrado.", "danger")
        conn.close()
        return redirect(url_for("index"))

    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        ip = request.form.get("ip", "").strip()
        plano_id = request.form.get("plano_id", "").strip()
        pool_id = request.form.get("pool_id", "").strip()

        if not plano_id:
            flash("Plano é obrigatório.", "danger")
            conn.close()
            return render_template("form_cliente.html", cliente=cliente, planos=planos, pools=pools)

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM planos WHERE id = %s", (plano_id,))
            plano_obj = cur.fetchone()

        if not plano_obj:
            flash("Plano selecionado não encontrado.", "danger")
            conn.close()
            return render_template("form_cliente.html", cliente=cliente, planos=planos, pools=pools)

        plano_nome = plano_obj["nome"]
        vel_down = plano_obj["velocidade_down"]
        vel_up = plano_obj["velocidade_up"]
        pool_id_val = int(pool_id) if pool_id else None

        if not check_ip_unique(conn, ip, cliente_id):
            flash(f"O IP {ip} já está em uso por outro cliente.", "danger")
            conn.close()
            return render_template("form_cliente.html", cliente=cliente, planos=planos, pools=pools)

        plano_changed = int(plano_id) != (cliente.get("plano_id") or 0)
        ip_changed = ip != (cliente.get("ip") or "")
        needs_disconnect = plano_changed or ip_changed

        with conn.cursor() as cur:
            cur.execute(
                """UPDATE clientes SET nome=%s, ip=%s, plano=%s, velocidade_down=%s,
                   velocidade_up=%s, plano_id=%s, pool_id=%s, atualizado_em=NOW() WHERE id=%s""",
                (nome, ip, plano_nome, vel_down, vel_up, int(plano_id), pool_id_val, cliente_id),
            )
        conn.commit()

        pppoe_login = cliente["pppoe_login"]
        if pppoe_login:
            upsert_radius_user(conn, pppoe_login, cliente["status"], vel_down, vel_up, ip)
            if needs_disconnect:
                if disconnect_user(conn, pppoe_login):
                    flash("Cliente atualizado. Sessão PPPoE derrubada para aplicar alterações.", "success")
                else:
                    flash("Cliente atualizado. Não foi possível derrubar a sessão — o cliente precisará reconectar.", "warning")
            else:
                flash("Cliente atualizado.", "success")
        else:
            flash("Cliente atualizado.", "success")

        conn.close()
        return redirect(url_for("index"))

    conn.close()
    return render_template("form_cliente.html", cliente=cliente, planos=planos, pools=pools)


@app.route("/cliente/<int:cliente_id>/sincronizar", methods=["POST"])
@login_required
def sincronizar_cliente(cliente_id):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM clientes WHERE id = %s", (cliente_id,))
        cliente = cur.fetchone()

    if not cliente:
        conn.close()
        return jsonify({"error": "Cliente não encontrado"}), 404

    contrato = consultar_sgp(cliente["cpf"])
    if not contrato:
        conn.close()
        return jsonify({"error": "CPF não encontrado no SGP"}), 422

    novo_status = status_from_sgp(contrato)
    pppoe_login = contrato.get("contratoCentralLogin") or cliente["pppoe_login"]
    ip_sgp = contrato.get("servico_ip") or cliente["ip"]

    if pppoe_login and not check_pppoe_login_unique(conn, pppoe_login, cliente_id):
        conn.close()
        return jsonify({"error": f"Login PPPoE '{pppoe_login}' já pertence a outro cliente"}), 409

    with conn.cursor() as cur:
        cur.execute(
            """UPDATE clientes SET status=%s, pppoe_login=%s, ip=%s,
               ultimo_sync_em=NOW(), atualizado_em=NOW() WHERE id=%s""",
            (novo_status, pppoe_login, ip_sgp, cliente_id),
        )
    conn.commit()

    if pppoe_login:
        upsert_radius_user(
            conn, pppoe_login, novo_status,
            cliente["velocidade_down"], cliente["velocidade_up"], ip_sgp,
        )

    conn.close()
    return jsonify({"status": novo_status, "pppoe_login": pppoe_login})


@app.route("/cliente/<int:cliente_id>/excluir", methods=["POST"])
@login_required
def excluir_cliente(cliente_id):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM clientes WHERE id = %s", (cliente_id,))
        cliente = cur.fetchone()

    if cliente:
        if cliente["pppoe_login"]:
            remove_radius_user(conn, cliente["pppoe_login"])
        with conn.cursor() as cur:
            cur.execute("DELETE FROM clientes WHERE id = %s", (cliente_id,))
        conn.commit()
        flash("Cliente removido.", "success")

    conn.close()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# CPF lookup AJAX
# ---------------------------------------------------------------------------

@app.route("/api/cpf/<cpf>")
@login_required
def api_cpf_lookup(cpf):
    cpf_clean = re.sub(r"\D", "", cpf)
    if len(cpf_clean) != 11:
        return jsonify({"error": "CPF inválido"}), 400
    contrato = consultar_sgp(cpf_clean)
    if not contrato:
        return jsonify({"error": "CPF não encontrado no SGP"}), 404
    return jsonify({
        "pppoe_login": contrato.get("contratoCentralLogin"),
        "status": status_from_sgp(contrato),
        "ip": contrato.get("servico_ip", ""),
        "nome": contrato.get("nomeCliente", ""),
    })


# ---------------------------------------------------------------------------
# Planos CRUD
# ---------------------------------------------------------------------------

@app.route("/planos", methods=["GET", "POST"])
@login_required
def gerenciar_planos():
    conn = get_db()
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        vel_down = request.form.get("velocidade_down", "10").strip()
        vel_up = request.form.get("velocidade_up", "5").strip()

        if nome and vel_down and vel_up:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO planos (nome, velocidade_down, velocidade_up) VALUES (%s, %s, %s)",
                        (nome, int(vel_down), int(vel_up)),
                    )
                conn.commit()
                flash("Plano criado com sucesso.", "success")
            except psycopg2.errors.UniqueViolation:
                conn.rollback()
                flash("Já existe um plano com este nome.", "danger")
        else:
            flash("Todos os campos são obrigatórios.", "danger")

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM planos ORDER BY nome")
        planos = cur.fetchall()

    conn.close()
    return render_template("planos.html", planos=planos)


@app.route("/planos/<int:plano_id>/excluir", methods=["POST"])
@login_required
def excluir_plano(plano_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM planos WHERE id = %s", (plano_id,))
    conn.commit()
    conn.close()
    flash("Plano removido.", "success")
    return redirect(url_for("gerenciar_planos"))


# ---------------------------------------------------------------------------
# Pools CRUD
# ---------------------------------------------------------------------------

@app.route("/pools", methods=["GET", "POST"])
@login_required
def gerenciar_pools():
    conn = get_db()
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        range_inicio = request.form.get("range_inicio", "").strip()
        range_fim = request.form.get("range_fim", "").strip()
        descricao = request.form.get("descricao", "").strip()

        if nome and range_inicio and range_fim:
            try:
                ipaddress.ip_address(range_inicio)
                ipaddress.ip_address(range_fim)
            except ValueError:
                flash("IPs do range são inválidos.", "danger")
                conn.close()
                return redirect(url_for("gerenciar_pools"))

            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO pools (nome, range_inicio, range_fim, descricao) VALUES (%s, %s, %s, %s)",
                        (nome, range_inicio, range_fim, descricao),
                    )
                conn.commit()
                flash("Pool criado com sucesso.", "success")
            except psycopg2.errors.UniqueViolation:
                conn.rollback()
                flash("Já existe um pool com este nome.", "danger")
        else:
            flash("Nome, IP inicial e IP final são obrigatórios.", "danger")

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM pools ORDER BY nome")
        pools = cur.fetchall()

    # Adiciona estatísticas de uso para cada pool
    for pool in pools:
        pool["stats"] = pool_stats(conn, pool["id"])

    conn.close()
    return render_template("pools.html", pools=pools)


@app.route("/pools/<int:pool_id>/excluir", methods=["POST"])
@login_required
def excluir_pool(pool_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM pools WHERE id = %s", (pool_id,))
    conn.commit()
    conn.close()
    flash("Pool removido.", "success")
    return redirect(url_for("gerenciar_pools"))


# ---------------------------------------------------------------------------
# NAS CRUD
# ---------------------------------------------------------------------------

@app.route("/nas", methods=["GET", "POST"])
@login_required
def gerenciar_nas():
    conn = get_db()
    if request.method == "POST":
        nasname = request.form.get("nasname", "").strip()
        shortname = request.form.get("shortname", "").strip()
        secret = request.form.get("secret", "").strip()
        description = request.form.get("description", "MikroTik").strip()
        mikrotik_user = request.form.get("mikrotik_user", "admin").strip()
        mikrotik_pass = request.form.get("mikrotik_pass", "").strip()

        if nasname and secret:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO nas (nasname, shortname, type, secret, description,
                       mikrotik_user, mikrotik_pass)
                       VALUES (%s, %s, 'other', %s, %s, %s, %s)""",
                    (nasname, shortname, secret, description, mikrotik_user, mikrotik_pass),
                )
            conn.commit()
            flash("NAS adicionado com sucesso.", "success")

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM nas ORDER BY id")
        nas_list = cur.fetchall()

    conn.close()
    return render_template("nas.html", nas_list=nas_list, mikrotik_available=MIKROTIK_AVAILABLE)


@app.route("/nas/<int:nas_id>/excluir", methods=["POST"])
@login_required
def excluir_nas(nas_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM nas WHERE id = %s", (nas_id,))
    conn.commit()
    conn.close()
    flash("NAS removido.", "success")
    return redirect(url_for("gerenciar_nas"))


@app.route("/nas/<int:nas_id>/sessoes")
@login_required
def nas_sessoes(nas_id):
    """Consulta sessões PPPoE ativas no MikroTik via RouterOS API."""
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM nas WHERE id = %s", (nas_id,))
        nas = cur.fetchone()
    conn.close()

    if not nas:
        return jsonify({"error": "NAS não encontrado"}), 404

    if not MIKROTIK_AVAILABLE:
        return jsonify({"error": "librouteros não instalado no servidor"}), 503

    mt_user = nas.get("mikrotik_user") or "admin"
    mt_pass = nas.get("mikrotik_pass") or ""

    try:
        api = librouteros.connect(
            host=nas["nasname"],
            username=mt_user,
            password=mt_pass,
            port=8728,
            timeout=5,
        )
        raw = list(api("/ppp/active/print"))
        api.close()
        # Converte keys com hífen para underscore para JSON
        sessoes = [{k.replace("-", "_"): v for k, v in s.items()} for s in raw]
        return jsonify({"nas": nas["nasname"], "sessoes": sessoes, "total": len(sessoes)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# RADIUS diagnóstico
# ---------------------------------------------------------------------------

@app.route("/radius/debug/<username>")
@login_required
def radius_debug(username):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM radcheck WHERE username = %s", (username,))
        checks = cur.fetchall()
        cur.execute("SELECT * FROM radreply WHERE username = %s", (username,))
        replies = cur.fetchall()
    conn.close()
    return jsonify({"username": username, "radcheck": checks, "radreply": replies})


@app.route("/radius/reapply", methods=["POST"])
@login_required
def radius_reapply_all():
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM clientes WHERE pppoe_login IS NOT NULL AND pppoe_login != ''")
        clientes = cur.fetchall()

    count = 0
    for c in clientes:
        upsert_radius_user(conn, c["pppoe_login"], c["status"],
                           c["velocidade_down"], c["velocidade_up"], c["ip"] or "")
        count += 1

    conn.close()
    flash(f"Atributos RADIUS reaplicados para {count} clientes.", "success")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Usuários
# ---------------------------------------------------------------------------

@app.route("/usuarios")
@login_required
def gerenciar_usuarios():
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, username, role, ativo, criado_em, ultimo_acesso FROM usuarios ORDER BY criado_em"
        )
        usuarios = cur.fetchall()
    conn.close()
    return render_template("usuarios.html", usuarios=usuarios)


@app.route("/usuarios/novo", methods=["POST"])
@login_required
def novo_usuario():
    username = request.form.get("username", "").strip()
    senha = request.form.get("senha", "").strip()
    role = request.form.get("role", "admin").strip()

    if not username or not senha:
        flash("Usuário e senha são obrigatórios.", "danger")
        return redirect(url_for("gerenciar_usuarios"))

    if len(senha) < 6:
        flash("A senha deve ter pelo menos 6 caracteres.", "danger")
        return redirect(url_for("gerenciar_usuarios"))

    senha_hash = generate_password_hash(senha)
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO usuarios (username, senha_hash, role) VALUES (%s, %s, %s)",
                (username, senha_hash, role),
            )
        conn.commit()
        flash(f"Usuário '{username}' criado com sucesso.", "success")
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        flash("Já existe um usuário com este nome.", "danger")
    finally:
        conn.close()
    return redirect(url_for("gerenciar_usuarios"))


@app.route("/usuarios/<int:usuario_id>/excluir", methods=["POST"])
@login_required
def excluir_usuario(usuario_id):
    if usuario_id == session.get("usuario_id"):
        flash("Você não pode excluir seu próprio usuário.", "danger")
        return redirect(url_for("gerenciar_usuarios"))

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM usuarios WHERE id = %s", (usuario_id,))
    conn.commit()
    conn.close()
    flash("Usuário removido.", "success")
    return redirect(url_for("gerenciar_usuarios"))


@app.route("/usuarios/<int:usuario_id>/alterar-senha", methods=["POST"])
@login_required
def alterar_senha(usuario_id):
    nova_senha = request.form.get("nova_senha", "").strip()
    if len(nova_senha) < 6:
        flash("A senha deve ter pelo menos 6 caracteres.", "danger")
        return redirect(url_for("gerenciar_usuarios"))

    senha_hash = generate_password_hash(nova_senha)
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("UPDATE usuarios SET senha_hash = %s WHERE id = %s", (senha_hash, usuario_id))
    conn.commit()
    conn.close()
    flash("Senha alterada com sucesso.", "success")
    return redirect(url_for("gerenciar_usuarios"))


# ---------------------------------------------------------------------------
# API Keys
# ---------------------------------------------------------------------------

@app.route("/api-keys")
@login_required
def gerenciar_api_keys():
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, nome, ativo, criado_em, ultimo_uso FROM api_keys ORDER BY criado_em DESC"
        )
        keys = cur.fetchall()
    conn.close()
    return render_template("api_keys.html", keys=keys)


@app.route("/api-keys/novo", methods=["POST"])
@login_required
def nova_api_key():
    nome = request.form.get("nome", "").strip()
    if not nome:
        flash("Nome é obrigatório.", "danger")
        return redirect(url_for("gerenciar_api_keys"))

    raw_key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("INSERT INTO api_keys (nome, key_hash) VALUES (%s, %s)", (nome, key_hash))
    conn.commit()
    conn.close()

    flash(
        f"API Key criada para '<strong>{nome}</strong>': "
        f"<code class='user-select-all'>{raw_key}</code> — Copie agora, não será exibida novamente.",
        "success",
    )
    return redirect(url_for("gerenciar_api_keys"))


@app.route("/api-keys/<int:key_id>/excluir", methods=["POST"])
@login_required
def excluir_api_key(key_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM api_keys WHERE id = %s", (key_id,))
    conn.commit()
    conn.close()
    flash("API Key removida.", "success")
    return redirect(url_for("gerenciar_api_keys"))


@app.route("/api-keys/<int:key_id>/toggle", methods=["POST"])
@login_required
def toggle_api_key(key_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("UPDATE api_keys SET ativo = NOT ativo WHERE id = %s", (key_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("gerenciar_api_keys"))


# ---------------------------------------------------------------------------
# Notificações
# ---------------------------------------------------------------------------

@app.route("/notificacoes", methods=["GET", "POST"])
@login_required
def gerenciar_notificacoes():
    conn = get_db()
    if request.method == "POST":
        tipo = request.form.get("tipo", "").strip()
        destino = request.form.get("destino", "").strip()

        if tipo and destino:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO notificacoes_config (tipo, destino) VALUES (%s, %s)",
                    (tipo, destino),
                )
            conn.commit()
            flash("Notificação configurada com sucesso.", "success")
        else:
            flash("Tipo e destino são obrigatórios.", "danger")

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM notificacoes_config ORDER BY criado_em DESC")
        configs = cur.fetchall()
    conn.close()
    return render_template("notificacoes.html", configs=configs)


@app.route("/notificacoes/<int:config_id>/excluir", methods=["POST"])
@login_required
def excluir_notificacao(config_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM notificacoes_config WHERE id = %s", (config_id,))
    conn.commit()
    conn.close()
    flash("Configuração removida.", "success")
    return redirect(url_for("gerenciar_notificacoes"))


@app.route("/notificacoes/<int:config_id>/toggle", methods=["POST"])
@login_required
def toggle_notificacao(config_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("UPDATE notificacoes_config SET ativo = NOT ativo WHERE id = %s", (config_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("gerenciar_notificacoes"))


# ---------------------------------------------------------------------------
# REST API v1
# ---------------------------------------------------------------------------

@app.route("/api/v1/clientes")
@api_key_required
def api_listar_clientes():
    pagina = int(request.args.get("pagina", 1))
    por_pagina = min(int(request.args.get("por_pagina", 50)), 200)
    busca = request.args.get("busca", "").strip()
    status_filtro = request.args.get("status", "").strip()
    offset = (pagina - 1) * por_pagina

    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT username FROM radacct WHERE acctstoptime IS NULL")
        online = {r["username"] for r in cur.fetchall()}

        where = []
        params = []
        if busca:
            where.append("(nome ILIKE %s OR cpf ILIKE %s OR pppoe_login ILIKE %s)")
            like = f"%{busca}%"
            params.extend([like, like, like])
        if status_filtro in ("ativo", "suspenso", "pendente"):
            where.append("status = %s")
            params.append(status_filtro)

        where_sql = ("WHERE " + " AND ".join(where)) if where else ""
        cur.execute(f"SELECT COUNT(*) FROM clientes {where_sql}", params)
        total = cur.fetchone()["count"]
        cur.execute(
            f"SELECT * FROM clientes {where_sql} ORDER BY nome LIMIT %s OFFSET %s",
            params + [por_pagina, offset],
        )
        clientes = cur.fetchall()
    conn.close()

    result = []
    for c in clientes:
        d = dict(c)
        d["online"] = bool(d.get("pppoe_login") and d["pppoe_login"] in online)
        d["criado_em"] = str(d["criado_em"]) if d.get("criado_em") else None
        d["atualizado_em"] = str(d["atualizado_em"]) if d.get("atualizado_em") else None
        d["ultimo_sync_em"] = str(d["ultimo_sync_em"]) if d.get("ultimo_sync_em") else None
        result.append(d)

    return jsonify({"total": total, "pagina": pagina, "por_pagina": por_pagina, "clientes": result})


@app.route("/api/v1/clientes/<int:cliente_id>")
@api_key_required
def api_get_cliente(cliente_id):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM clientes WHERE id = %s", (cliente_id,))
        cliente = cur.fetchone()
        if cliente and cliente.get("pppoe_login"):
            cur.execute(
                "SELECT acctsessionid FROM radacct WHERE username = %s AND acctstoptime IS NULL LIMIT 1",
                (cliente["pppoe_login"],),
            )
            cliente["online"] = cur.fetchone() is not None
        else:
            if cliente:
                cliente["online"] = False
    conn.close()

    if not cliente:
        return jsonify({"error": "Cliente não encontrado"}), 404

    d = dict(cliente)
    for k in ("criado_em", "atualizado_em", "ultimo_sync_em"):
        if d.get(k):
            d[k] = str(d[k])
    return jsonify(d)


@app.route("/api/v1/clientes/<int:cliente_id>/status")
@api_key_required
def api_status_cliente(cliente_id):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id, nome, pppoe_login, status, ultimo_sync_em FROM clientes WHERE id = %s", (cliente_id,))
        cliente = cur.fetchone()
        online = False
        if cliente and cliente.get("pppoe_login"):
            cur.execute(
                "SELECT 1 FROM radacct WHERE username = %s AND acctstoptime IS NULL LIMIT 1",
                (cliente["pppoe_login"],),
            )
            online = cur.fetchone() is not None
    conn.close()

    if not cliente:
        return jsonify({"error": "Cliente não encontrado"}), 404

    return jsonify({
        "id": cliente["id"],
        "nome": cliente["nome"],
        "pppoe_login": cliente["pppoe_login"],
        "status": cliente["status"],
        "online": online,
        "ultimo_sync_em": str(cliente["ultimo_sync_em"]) if cliente.get("ultimo_sync_em") else None,
    })


@app.route("/api/v1/clientes/<int:cliente_id>/sincronizar", methods=["POST"])
@api_key_required
def api_sincronizar_cliente(cliente_id):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM clientes WHERE id = %s", (cliente_id,))
        cliente = cur.fetchone()
    if not cliente:
        conn.close()
        return jsonify({"error": "Cliente não encontrado"}), 404

    contrato = consultar_sgp(cliente["cpf"])
    if not contrato:
        conn.close()
        return jsonify({"error": "CPF não encontrado no SGP"}), 422

    novo_status = status_from_sgp(contrato)
    pppoe_login = contrato.get("contratoCentralLogin") or cliente["pppoe_login"]
    ip_sgp = contrato.get("servico_ip") or cliente["ip"]

    with conn.cursor() as cur:
        cur.execute(
            """UPDATE clientes SET status=%s, pppoe_login=%s, ip=%s,
               ultimo_sync_em=NOW(), atualizado_em=NOW() WHERE id=%s""",
            (novo_status, pppoe_login, ip_sgp, cliente_id),
        )
    conn.commit()

    if pppoe_login:
        upsert_radius_user(conn, pppoe_login, novo_status,
                           cliente["velocidade_down"], cliente["velocidade_up"], ip_sgp)
    conn.close()
    return jsonify({"status": novo_status, "pppoe_login": pppoe_login})


@app.route("/api/v1/online")
@api_key_required
def api_online():
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT ra.username, ra.nasipaddress, ra.acctstarttime,
                   ra.acctinputoctets, ra.acctoutputoctets, ra.framedipaddress,
                   c.nome, c.plano
            FROM radacct ra
            LEFT JOIN clientes c ON c.pppoe_login = ra.username
            WHERE ra.acctstoptime IS NULL
            ORDER BY ra.acctstarttime DESC
        """)
        sessoes = cur.fetchall()
    conn.close()
    result = []
    for s in sessoes:
        d = dict(s)
        d["acctstarttime"] = str(d["acctstarttime"]) if d.get("acctstarttime") else None
        d["nasipaddress"] = str(d["nasipaddress"]) if d.get("nasipaddress") else None
        d["framedipaddress"] = str(d["framedipaddress"]) if d.get("framedipaddress") else None
        result.append(d)
    return jsonify({"total": len(result), "sessoes": result})


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

with app.app_context():
    create_default_admin()

if __name__ == "__main__":
    app.run(debug=False)
