import os
import re
import requests
import psycopg2
import psycopg2.extras
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

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


def _plano_to_speeds(plano: str):
    """Tenta extrair velocidade do nome do plano (ex: '100M', '50MEGA').
    Retorna (down_mbps, up_mbps)."""
    match = re.search(r"(\d+)\s*[Mm]", plano)
    if match:
        down = int(match.group(1))
        up = max(5, down // 4)
        return down, up
    return 10, 5  # padrão


# ---------------------------------------------------------------------------
# SGP helpers
# ---------------------------------------------------------------------------

SGP_URL = os.environ.get("SGP_URL", "https://linknetam.sgp.net.br/api/ura/consultacliente/")
SGP_TOKEN = os.environ.get("SGP_TOKEN", "8e6523a9-2c7e-43de-888b-555da380a8fd")
SGP_APP = os.environ.get("SGP_APP", "bot")


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
    """Retorna 'ativo' ou 'suspenso' baseado no contratoStatusDisplay."""
    display = contrato.get("contratoStatusDisplay", "").lower()
    if display == "ativo":
        return "ativo"
    return "suspenso"


# ---------------------------------------------------------------------------
# RADIUS helpers — escrevem diretamente nas tabelas do FreeRADIUS
# ---------------------------------------------------------------------------

def _speed_attr(mbps: int) -> str:
    """Converte Mbps para bps (atributo Mikrotik-Rate-Limit)."""
    return f"{mbps}M/{mbps}M"


def upsert_radius_user(conn, login: str, status: str, down: int, up: int):
    """Insere ou atualiza entradas no radcheck e radreply para o usuário PPPoE."""
    with conn.cursor() as cur:
        # Remove entradas antigas
        cur.execute("DELETE FROM radcheck WHERE username = %s", (login,))
        cur.execute("DELETE FROM radreply WHERE username = %s", (login,))

        if status == "ativo":
            # Senha sempre '123' conforme regra de negócio
            cur.execute(
                "INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, %s, %s, %s)",
                (login, "Cleartext-Password", ":=", "123"),
            )
            # Velocidade via atributo Mikrotik-Rate-Limit
            rate = f"{up}M/{down}M"
            cur.execute(
                "INSERT INTO radreply (username, attribute, op, value) VALUES (%s, %s, %s, %s)",
                (login, "Mikrotik-Rate-Limit", ":=", rate),
            )
            # Framed-IP-Address será preenchido se tivermos o IP do SGP
        else:
            # Usuário suspenso: Auth-Type = Reject
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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM clientes ORDER BY criado_em DESC")
        clientes = cur.fetchall()
    conn.close()
    return render_template("index.html", clientes=clientes)


@app.route("/cliente/novo", methods=["GET", "POST"])
def novo_cliente():
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        cpf = re.sub(r"\D", "", request.form.get("cpf", ""))
        ip = request.form.get("ip", "").strip()
        plano = request.form.get("plano", "").strip()
        vel_down = request.form.get("velocidade_down", "10").strip()
        vel_up = request.form.get("velocidade_up", "5").strip()

        if not nome or not cpf or not plano:
            flash("Nome, CPF e Plano são obrigatórios.", "danger")
            return render_template("form_cliente.html", cliente=None)

        # Consulta SGP para obter login PPPoE e status
        contrato = consultar_sgp(cpf)
        pppoe_login = None
        status = "pendente"

        if contrato:
            pppoe_login = contrato.get("contratoCentralLogin")
            status = status_from_sgp(contrato)
            # Usar IP do SGP se não informado
            if not ip:
                ip = contrato.get("servico_ip", "")
            # Usar plano do SGP
            if not plano:
                plano = contrato.get("servico_plano", plano)
        else:
            flash("Aviso: não foi possível consultar o SGP. Cliente salvo como pendente.", "warning")

        try:
            vel_down = int(vel_down)
            vel_up = int(vel_up)
        except ValueError:
            vel_down, vel_up = _plano_to_speeds(plano)

        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO clientes (nome, cpf, ip, plano, velocidade_down, velocidade_up, pppoe_login, status)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                    (nome, cpf, ip, plano, vel_down, vel_up, pppoe_login, status),
                )
            conn.commit()

            if pppoe_login:
                upsert_radius_user(conn, pppoe_login, status, vel_down, vel_up)

            flash(f"Cliente cadastrado com sucesso! Status SGP: {status}", "success")
        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            flash("Já existe um cliente com este CPF.", "danger")
        finally:
            conn.close()

        return redirect(url_for("index"))

    return render_template("form_cliente.html", cliente=None)


@app.route("/cliente/<int:cliente_id>/editar", methods=["GET", "POST"])
def editar_cliente(cliente_id):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM clientes WHERE id = %s", (cliente_id,))
        cliente = cur.fetchone()

    if not cliente:
        flash("Cliente não encontrado.", "danger")
        conn.close()
        return redirect(url_for("index"))

    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        ip = request.form.get("ip", "").strip()
        plano = request.form.get("plano", "").strip()
        vel_down = int(request.form.get("velocidade_down", 10))
        vel_up = int(request.form.get("velocidade_up", 5))

        with conn.cursor() as cur:
            cur.execute(
                """UPDATE clientes SET nome=%s, ip=%s, plano=%s, velocidade_down=%s,
                   velocidade_up=%s, atualizado_em=NOW() WHERE id=%s""",
                (nome, ip, plano, vel_down, vel_up, cliente_id),
            )
        conn.commit()

        pppoe_login = cliente["pppoe_login"]
        if pppoe_login:
            upsert_radius_user(conn, pppoe_login, cliente["status"], vel_down, vel_up)

        flash("Cliente atualizado.", "success")
        conn.close()
        return redirect(url_for("index"))

    conn.close()
    return render_template("form_cliente.html", cliente=cliente)


@app.route("/cliente/<int:cliente_id>/sincronizar", methods=["POST"])
def sincronizar_cliente(cliente_id):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM clientes WHERE id = %s", (cliente_id,))
        cliente = cur.fetchone()

    if not cliente:
        conn.close()
        return jsonify({"error": "Cliente não encontrado"}), 404

    cpf = cliente["cpf"]
    contrato = consultar_sgp(cpf)

    if not contrato:
        conn.close()
        return jsonify({"error": "CPF não encontrado no SGP"}), 422

    novo_status = status_from_sgp(contrato)
    pppoe_login = contrato.get("contratoCentralLogin") or cliente["pppoe_login"]
    ip_sgp = contrato.get("servico_ip") or cliente["ip"]

    with conn.cursor() as cur:
        cur.execute(
            """UPDATE clientes SET status=%s, pppoe_login=%s, ip=%s, atualizado_em=NOW()
               WHERE id=%s""",
            (novo_status, pppoe_login, ip_sgp, cliente_id),
        )
    conn.commit()

    if pppoe_login:
        upsert_radius_user(
            conn, pppoe_login, novo_status,
            cliente["velocidade_down"], cliente["velocidade_up"]
        )

    conn.close()
    return jsonify({"status": novo_status, "pppoe_login": pppoe_login})


@app.route("/cliente/<int:cliente_id>/excluir", methods=["POST"])
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


@app.route("/nas", methods=["GET", "POST"])
def gerenciar_nas():
    conn = get_db()
    if request.method == "POST":
        nasname = request.form.get("nasname", "").strip()
        shortname = request.form.get("shortname", "").strip()
        secret = request.form.get("secret", "").strip()
        description = request.form.get("description", "MikroTik").strip()

        if nasname and secret:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO nas (nasname, shortname, type, secret, description)
                       VALUES (%s, %s, 'other', %s, %s)""",
                    (nasname, shortname, secret, description),
                )
            conn.commit()
            flash("NAS adicionado com sucesso.", "success")

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM nas ORDER BY id")
        nas_list = cur.fetchall()

    conn.close()
    return render_template("nas.html", nas_list=nas_list)


@app.route("/nas/<int:nas_id>/excluir", methods=["POST"])
def excluir_nas(nas_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM nas WHERE id = %s", (nas_id,))
    conn.commit()
    conn.close()
    flash("NAS removido.", "success")
    return redirect(url_for("gerenciar_nas"))


if __name__ == "__main__":
    app.run(debug=False)
