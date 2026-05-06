"""
Mini App backend — Flask leve.

Rotas:
  GET  /                — serve a SPA (static/index.html)
  GET  /static/*        — assets
  POST /api/me          — valida initData + retorna user info (autorização)
  GET  /healthz         — para o nginx-proxy-manager checar
"""
import os
import re
import json
import subprocess
import logging
import urllib.parse
from functools import wraps

import requests
from flask import Flask, jsonify, request, send_from_directory
import psycopg2
import psycopg2.extras

from auth import validate_init_data, get_authorized_user
from mikrotik import online_via_mikrotik, online_logins_set, probe_all_nas
import time
import hashlib
import secrets

try:
    import librouteros
    MIKROTIK_AVAILABLE = True
except ImportError:
    MIKROTIK_AVAILABLE = False
from werkzeug.security import generate_password_hash
from audit import log_audit

GENIEACS_NBI_URL = os.environ.get("GENIEACS_NBI_URL", "http://genieacs-nbi:7557").rstrip("/")

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"miniapp","msg":"%(message)s"}',
)
log = logging.getLogger("miniapp")

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

app = Flask(__name__, static_folder=None)


def get_db():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "postgres"),
        dbname=os.environ.get("DB_NAME", "radius"),
        user=os.environ.get("DB_USER", "radius"),
        password=os.environ.get("DB_PASS", "radiuspassword"),
    )


def get_bot_token():
    """Lê o bot token de alertas_config.telegram_bot_token."""
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT valor FROM alertas_config WHERE chave='telegram_bot_token'")
            row = cur.fetchone()
        conn.close()
        return row[0] if row and row[0] else None
    except Exception:
        return None


def require_telegram_auth(f):
    """
    Decorator que:
    1. Lê initData do header X-Telegram-Init-Data
    2. Valida HMAC
    3. Verifica whitelist em mini_app_users
    4. Injeta `g_user` no request via flask.g
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask import g
        init_data = request.headers.get("X-Telegram-Init-Data", "")
        token = get_bot_token()
        if not token:
            return jsonify({"error": "Bot token não configurado"}), 500

        parsed = validate_init_data(init_data, token)
        if not parsed:
            return jsonify({"error": "initData inválido ou expirado"}), 401

        user_payload = parsed.get("user") or {}
        tg_user_id = user_payload.get("id")
        if not tg_user_id:
            return jsonify({"error": "user.id ausente no initData"}), 401

        authorized = get_authorized_user(get_db, tg_user_id)
        if not authorized:
            return jsonify({
                "error": "não autorizado",
                "hint": f"peça ao admin para adicionar telegram_user_id={tg_user_id} em mini_app_users",
                "telegram_user_id": tg_user_id,
            }), 403

        g.tg_user = user_payload
        g.app_user = authorized
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Static / SPA
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/static/<path:path>")
def static_files(path):
    return send_from_directory(STATIC_DIR, path)


@app.route("/healthz")
def healthz():
    try:
        conn = get_db()
        conn.cursor().execute("SELECT 1")
        conn.close()
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 503


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

@app.route("/api/me", methods=["POST"])
@require_telegram_auth
def api_me():
    from flask import g
    return jsonify({
        "telegram": {
            "id":         g.tg_user.get("id"),
            "username":   g.tg_user.get("username"),
            "first_name": g.tg_user.get("first_name"),
            "last_name":  g.tg_user.get("last_name"),
            "language":   g.tg_user.get("language_code"),
        },
        "authorized": True,
        "role":       g.app_user.get("role"),
        "nome":       g.app_user.get("nome"),
    })


# Endpoint de teste sem auth — só pra validar que servidor sobe
@app.route("/api/ping")
def api_ping():
    return jsonify({"pong": True, "service": "mini-app"})


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/api/dashboard")
@require_telegram_auth
def api_dashboard():
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    (SELECT COUNT(*) FROM clientes)                            AS total,
                    (SELECT COUNT(*) FROM clientes WHERE status='ativo')       AS ativos,
                    (SELECT COUNT(*) FROM clientes WHERE status='suspenso')    AS suspensos,
                    (SELECT COUNT(*) FROM clientes WHERE status='pendente')    AS pendentes,
                    (SELECT COUNT(*) FROM cpe_devices WHERE online=TRUE)       AS cpes_online,
                    (SELECT COUNT(*) FROM cpe_devices WHERE online=FALSE)      AS cpes_offline,
                    (SELECT COUNT(*) FROM chamados WHERE status='aberto')      AS chamados_abertos,
                    (SELECT COUNT(*) FROM alert_state WHERE firing=TRUE)       AS alertas_firing,
                    (SELECT COUNT(*) FROM nas)                                 AS nas_total
            """)
            kpis = cur.fetchone()
    finally:
        conn.close()

    # Online real via MikroTik (radacct é fallback)
    sessoes = online_via_mikrotik(get_db)
    if sessoes is not None:
        kpis["online"] = len(sessoes)
        kpis["online_source"] = "mikrotik"
    else:
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM radacct WHERE acctstoptime IS NULL")
                kpis["online"] = cur.fetchone()[0]
            kpis["online_source"] = "radacct"
        finally:
            conn.close()

    return jsonify(kpis)


# ---------------------------------------------------------------------------
# Clientes — busca e detalhe
# ---------------------------------------------------------------------------

@app.route("/api/clientes/buscar")
@require_telegram_auth
def api_clientes_buscar():
    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify({"clientes": [], "msg": "digite ao menos 2 caracteres"})

    cpf_limpo = re.sub(r"\D", "", q)
    like = f"%{q}%"

    online_set = online_logins_set(get_db)

    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Busca por CPF (limpo), nome ILIKE, login ILIKE
            cur.execute("""
                SELECT id, nome, cpf, pppoe_login, status, ip, plano,
                       velocidade_down, velocidade_up
                  FROM clientes
                 WHERE cpf = %s
                    OR nome ILIKE %s
                    OR pppoe_login ILIKE %s
              ORDER BY nome
                 LIMIT 50
            """, (cpf_limpo, like, like))
            rows = cur.fetchall()
    finally:
        conn.close()

    clientes = []
    for r in rows:
        d = dict(r)
        d["online"] = d.get("pppoe_login") in online_set
        clientes.append(d)
    return jsonify({"clientes": clientes, "total": len(clientes)})


@app.route("/api/clientes/<int:cliente_id>")
@require_telegram_auth
def api_cliente_detalhe(cliente_id):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT c.*, p.nome AS plano_nome, po.nome AS pool_nome
                  FROM clientes c
                  LEFT JOIN planos p ON p.id = c.plano_id
                  LEFT JOIN pools  po ON po.id = c.pool_id
                 WHERE c.id = %s
            """, (cliente_id,))
            cli = cur.fetchone()
            if not cli:
                return jsonify({"error": "cliente não encontrado"}), 404

            cur.execute("""
                SELECT acctstarttime, framedipaddress::text AS ip,
                       nasipaddress::text AS nas,
                       acctinputoctets, acctoutputoctets,
                       acctsessionid
                  FROM radacct
                 WHERE username = %s AND acctstoptime IS NULL
              ORDER BY acctstarttime DESC LIMIT 1
            """, (cli["pppoe_login"],))
            sessao = cur.fetchone()

            cur.execute("""
                SELECT id, modelo, fabricante, online, rx_power, ip_wan, ssid,
                       genieacs_id, ultima_conexao
                  FROM cpe_devices
                 WHERE cliente_id = %s
              ORDER BY id LIMIT 1
            """, (cliente_id,))
            cpe = cur.fetchone()
    finally:
        conn.close()

    cli_d = {k: (str(v) if hasattr(v, "isoformat") else v) for k, v in dict(cli).items()}
    if sessao:
        sessao_d = {k: (str(v) if hasattr(v, "isoformat") else v) for k, v in dict(sessao).items()}
        sessao_d["traffic"] = (sessao_d.get("acctinputoctets") or 0) + (sessao_d.get("acctoutputoctets") or 0)
    else:
        sessao_d = None
    if cpe:
        cpe_d = {k: (str(v) if hasattr(v, "isoformat") else v) for k, v in dict(cpe).items()}
    else:
        cpe_d = None

    return jsonify({"cliente": cli_d, "sessao": sessao_d, "cpe": cpe_d})


# ---------------------------------------------------------------------------
# Ações sobre clientes
# ---------------------------------------------------------------------------

def _radclient_disconnect(nas_ip, secret, login):
    try:
        proc = subprocess.run(
            ["radclient", "-x", f"{nas_ip}:3799", "disconnect", secret],
            input=f'User-Name="{login}"',
            capture_output=True, text=True, timeout=10,
        )
        return proc.returncode == 0, proc.stdout + proc.stderr
    except FileNotFoundError:
        return False, "radclient não encontrado"
    except Exception as e:
        return False, str(e)


def _get_active_session_nas(conn, login):
    """Retorna (nas_ip, secret) da sessão ativa, ou (None, None)."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT nasipaddress::text AS nas_ip
              FROM radacct
             WHERE username = %s AND acctstoptime IS NULL
          ORDER BY acctstarttime DESC LIMIT 1
        """, (login,))
        sessao = cur.fetchone()
        if not sessao:
            return None, None
        nas_ip = sessao["nas_ip"]
        cur.execute("SELECT secret FROM nas WHERE nasname = %s", (nas_ip,))
        nas_row = cur.fetchone()
        return nas_ip, (nas_row["secret"] if nas_row else "testing123")


@app.route("/api/clientes/<int:cliente_id>/desconectar", methods=["POST"])
@require_telegram_auth
def api_cliente_desconectar(cliente_id):
    from flask import g
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT pppoe_login, nome FROM clientes WHERE id=%s", (cliente_id,))
            cli = cur.fetchone()
            if not cli or not cli["pppoe_login"]:
                return jsonify({"error": "cliente sem login PPPoE"}), 400
            nas_ip, secret = _get_active_session_nas(conn, cli["pppoe_login"])
    finally:
        conn.close()

    if not nas_ip:
        return jsonify({"ok": False, "msg": "cliente não tem sessão ativa"}), 200

    log_audit(get_db, g.app_user, "miniapp:desconectar",
              target_type="cliente", target_id=cliente_id,
              detail={"login": cli["pppoe_login"], "nas_ip": nas_ip})

    ok, out = _radclient_disconnect(nas_ip, secret, cli["pppoe_login"])
    return jsonify({"ok": ok, "msg": "desconectado" if ok else "CoA falhou", "detail": out[:500]})


@app.route("/api/clientes/<int:cliente_id>/bloquear", methods=["POST"])
@require_telegram_auth
def api_cliente_bloquear(cliente_id):
    from flask import g
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT pppoe_login, nome FROM clientes WHERE id=%s", (cliente_id,))
            cli = cur.fetchone()
            if not cli or not cli["pppoe_login"]:
                return jsonify({"error": "cliente sem login PPPoE"}), 400
            login = cli["pppoe_login"]

            # Aplica rate limit de 128k/128k (efetivamente bloqueado)
            cur.execute("DELETE FROM radreply WHERE username=%s AND attribute='Mikrotik-Rate-Limit'", (login,))
            cur.execute("INSERT INTO radreply (username,attribute,op,value) VALUES (%s,'Mikrotik-Rate-Limit',':=','128k/128k')", (login,))
            conn.commit()

            nas_ip, secret = _get_active_session_nas(conn, login)
    finally:
        conn.close()

    log_audit(get_db, g.app_user, "miniapp:bloquear",
              target_type="cliente", target_id=cliente_id,
              detail={"login": login, "nas_ip": nas_ip})

    detail = ""
    if nas_ip:
        ok, out = _radclient_disconnect(nas_ip, secret, login)
        detail = out[:500]

    return jsonify({"ok": True, "msg": f"bloqueado: rate limitado a 128k. CoA disconnect enviado para {nas_ip or 'sem sessão ativa'}"})


@app.route("/api/clientes/<int:cliente_id>/desbloquear", methods=["POST"])
@require_telegram_auth
def api_cliente_desbloquear(cliente_id):
    from flask import g
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT pppoe_login, velocidade_down, velocidade_up
                  FROM clientes WHERE id=%s
            """, (cliente_id,))
            cli = cur.fetchone()
            if not cli or not cli["pppoe_login"]:
                return jsonify({"error": "cliente sem login PPPoE"}), 400
            login = cli["pppoe_login"]
            rate = f"{cli['velocidade_up']}M/{cli['velocidade_down']}M"

            cur.execute("DELETE FROM radreply WHERE username=%s AND attribute='Mikrotik-Rate-Limit'", (login,))
            cur.execute("INSERT INTO radreply (username,attribute,op,value) VALUES (%s,'Mikrotik-Rate-Limit',':=',%s)", (login, rate))
            conn.commit()

            nas_ip, secret = _get_active_session_nas(conn, login)
    finally:
        conn.close()

    log_audit(get_db, g.app_user, "miniapp:desbloquear",
              target_type="cliente", target_id=cliente_id,
              detail={"login": login, "rate": rate})

    if nas_ip:
        _radclient_disconnect(nas_ip, secret, login)

    return jsonify({"ok": True, "msg": f"desbloqueado: {rate}. Cliente vai reconectar."})


@app.route("/api/clientes/<int:cliente_id>/reaplicar", methods=["POST"])
@require_telegram_auth
def api_cliente_reaplicar(cliente_id):
    from flask import g
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM clientes WHERE id=%s", (cliente_id,))
            cli = cur.fetchone()
            if not cli or not cli["pppoe_login"]:
                return jsonify({"error": "cliente sem login PPPoE"}), 400
            login = cli["pppoe_login"]

            # Preserva senha existente
            cur.execute("SELECT value FROM radcheck WHERE username=%s AND attribute='Cleartext-Password'", (login,))
            row = cur.fetchone()
            senha = row["value"] if row else "123"

            cur.execute("DELETE FROM radcheck WHERE username = %s", (login,))
            cur.execute("DELETE FROM radreply WHERE username = %s", (login,))

            if cli["status"] == "ativo":
                cur.execute("INSERT INTO radcheck (username,attribute,op,value) VALUES (%s,'Cleartext-Password',':=',%s)", (login, senha))
                rate = f"{cli['velocidade_up']}M/{cli['velocidade_down']}M"
                cur.execute("INSERT INTO radreply (username,attribute,op,value) VALUES (%s,'Mikrotik-Rate-Limit',':=',%s)", (login, rate))
                if cli.get("ip"):
                    cur.execute("INSERT INTO radreply (username,attribute,op,value) VALUES (%s,'Framed-IP-Address',':=',%s)", (login, cli["ip"]))
            elif cli["status"] == "suspenso":
                cur.execute("INSERT INTO radcheck (username,attribute,op,value) VALUES (%s,'Cleartext-Password',':=',%s)", (login, senha))
            else:
                cur.execute("INSERT INTO radcheck (username,attribute,op,value) VALUES (%s,'Auth-Type',':=','Reject')", (login,))
            conn.commit()
    finally:
        conn.close()

    log_audit(get_db, g.app_user, "miniapp:reaplicar",
              target_type="cliente", target_id=cliente_id,
              detail={"login": login, "status": cli["status"]})

    return jsonify({"ok": True, "msg": f"atributos RADIUS reaplicados (status={cli['status']})"})


# ---------------------------------------------------------------------------
# Reboot CPE via GenieACS NBI
# ---------------------------------------------------------------------------

@app.route("/api/cpe/<int:cpe_id>/reboot", methods=["POST"])
@require_telegram_auth
def api_cpe_reboot(cpe_id):
    from flask import g
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT genieacs_id, modelo, serial_number FROM cpe_devices WHERE id=%s", (cpe_id,))
            cpe = cur.fetchone()
            if not cpe or not cpe["genieacs_id"]:
                return jsonify({"error": "CPE sem genieacs_id"}), 404
    finally:
        conn.close()

    log_audit(get_db, g.app_user, "miniapp:cpe_reboot",
              target_type="cpe", target_id=cpe_id,
              detail={"modelo": cpe.get("modelo"), "serial": cpe.get("serial_number")})

    encoded = urllib.parse.quote(cpe["genieacs_id"], safe="")
    try:
        r = requests.post(
            f"{GENIEACS_NBI_URL}/devices/{encoded}/tasks?timeout=3000&connection_request",
            json={"name": "reboot"},
            timeout=12,
        )
        if r.ok:
            return jsonify({"ok": True, "msg": "reboot enviado ao CPE"})
        return jsonify({"ok": False, "msg": f"GenieACS retornou {r.status_code}", "detail": r.text[:300]}), 502
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 502


# ---------------------------------------------------------------------------
# NAS — lista com métricas
# ---------------------------------------------------------------------------

@app.route("/api/nas")
@require_telegram_auth
def api_nas():
    return jsonify({"nas": probe_all_nas(get_db)})


# ---------------------------------------------------------------------------
# CPEs — lista com filtros
# ---------------------------------------------------------------------------

@app.route("/api/cpes")
@require_telegram_auth
def api_cpes():
    filtro = (request.args.get("filtro") or "todos").lower()
    q = (request.args.get("q") or "").strip()

    where = []
    params = []

    if filtro == "online":
        where.append("cpe.online = TRUE")
    elif filtro == "offline":
        where.append("cpe.online = FALSE")
    elif filtro == "critico":
        # Rx Power < -27 dBm OU offline
        where.append("(cpe.rx_power IS NOT NULL AND cpe.rx_power < -27) OR cpe.online = FALSE")

    if q:
        where.append("(c.nome ILIKE %s OR cpe.serial_number ILIKE %s OR cpe.modelo ILIKE %s)")
        like = f"%{q}%"
        params.extend([like, like, like])

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"""
                SELECT cpe.id, cpe.modelo, cpe.fabricante, cpe.online, cpe.rx_power,
                       cpe.ip_wan, cpe.serial_number, cpe.ultima_conexao,
                       cpe.cliente_id, c.nome AS cliente_nome, c.pppoe_login
                  FROM cpe_devices cpe
                  LEFT JOIN clientes c ON c.id = cpe.cliente_id
                  {where_sql}
              ORDER BY cpe.online, cpe.rx_power NULLS LAST, cpe.id
                 LIMIT 200
            """, params)
            rows = cur.fetchall()
    finally:
        conn.close()

    cpes = []
    for r in rows:
        d = dict(r)
        if d.get("ultima_conexao"):
            d["ultima_conexao"] = str(d["ultima_conexao"])
        if d.get("rx_power") is not None:
            d["rx_power"] = float(d["rx_power"])
        cpes.append(d)
    return jsonify({"cpes": cpes, "total": len(cpes), "filtro": filtro})


@app.route("/api/cpe/<int:cpe_id>/refresh", methods=["POST"])
@require_telegram_auth
def api_cpe_refresh(cpe_id):
    """Força o CPE a se conectar ao ACS imediatamente."""
    from flask import g
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT genieacs_id FROM cpe_devices WHERE id=%s", (cpe_id,))
            cpe = cur.fetchone()
            if not cpe or not cpe["genieacs_id"]:
                return jsonify({"error": "CPE sem genieacs_id"}), 404
    finally:
        conn.close()

    log_audit(get_db, g.app_user, "miniapp:cpe_refresh", target_type="cpe", target_id=cpe_id)

    encoded = urllib.parse.quote(cpe["genieacs_id"], safe="")
    try:
        r = requests.post(
            f"{GENIEACS_NBI_URL}/devices/{encoded}/tasks?connection_request",
            json={"name": "getParameterValues", "parameterNames": ["Device.DeviceInfo."]},
            timeout=12,
        )
        if r.ok:
            return jsonify({"ok": True, "msg": "refresh enviado ao CPE"})
        return jsonify({"ok": False, "msg": f"GenieACS {r.status_code}"}), 502
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 502


# ---------------------------------------------------------------------------
# Chamados
# ---------------------------------------------------------------------------

@app.route("/api/chamados")
@require_telegram_auth
def api_chamados():
    status_filtro = (request.args.get("status") or "aberto").lower()

    where = ""
    params = []
    if status_filtro != "todos":
        where = "WHERE ch.status = %s"
        params = [status_filtro]

    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"""
                SELECT ch.id, ch.tipo, ch.status, ch.descricao,
                       ch.criado_em, ch.resolvido_em,
                       ch.cliente_id, c.nome AS cliente_nome, c.pppoe_login,
                       ch.cpe_id, cpe.modelo AS cpe_modelo, cpe.rx_power
                  FROM chamados ch
                  LEFT JOIN clientes c ON c.id = ch.cliente_id
                  LEFT JOIN cpe_devices cpe ON cpe.id = ch.cpe_id
                  {where}
              ORDER BY ch.criado_em DESC
                 LIMIT 100
            """, params)
            rows = cur.fetchall()
    finally:
        conn.close()

    chamados = []
    for r in rows:
        d = dict(r)
        for k in ("criado_em", "resolvido_em"):
            if d.get(k):
                d[k] = str(d[k])
        if d.get("rx_power") is not None:
            d["rx_power"] = float(d["rx_power"])
        chamados.append(d)
    return jsonify({"chamados": chamados, "total": len(chamados), "status": status_filtro})


@app.route("/api/chamados/<int:chamado_id>/resolver", methods=["POST"])
@require_telegram_auth
def api_chamados_resolver(chamado_id):
    from flask import g
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE chamados
                   SET status='resolvido', resolvido_em=NOW(), atualizado_em=NOW()
                 WHERE id=%s AND status='aberto'
            """, (chamado_id,))
            affected = cur.rowcount
        conn.commit()
    finally:
        conn.close()

    if affected == 0:
        return jsonify({"ok": False, "msg": "chamado não encontrado ou já resolvido"}), 404

    log_audit(get_db, g.app_user, "miniapp:chamado_resolver",
              target_type="chamado", target_id=chamado_id)
    return jsonify({"ok": True, "msg": "chamado marcado como resolvido"})


# ---------------------------------------------------------------------------
# Manutenções (silenciar alertas)
# ---------------------------------------------------------------------------

@app.route("/api/manutencoes")
@require_telegram_auth
def api_manutencoes_list():
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, inicio, fim, escopo, motivo, criado_por, criado_em,
                       (fim > NOW()) AS ativa
                  FROM maintenance_window
              ORDER BY criado_em DESC
                 LIMIT 50
            """)
            rows = cur.fetchall()
    finally:
        conn.close()

    out = []
    for r in rows:
        d = dict(r)
        for k in ("inicio", "fim", "criado_em"):
            if d.get(k):
                d[k] = str(d[k])
        out.append(d)
    return jsonify({"manutencoes": out})


@app.route("/api/manutencoes", methods=["POST"])
@require_telegram_auth
def api_manutencoes_create():
    from flask import g
    body = request.get_json(silent=True) or {}
    minutos = int(body.get("minutos") or 0)
    motivo = (body.get("motivo") or "").strip() or None

    if minutos < 1 or minutos > 7 * 24 * 60:
        return jsonify({"error": "minutos inválido (1..10080)"}), 400

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO maintenance_window (inicio, fim, escopo, motivo, criado_por)
                VALUES (NOW(), NOW() + (%s * INTERVAL '1 minute'), 'all', %s, %s)
                RETURNING id
            """, (minutos, motivo, f"miniapp:{g.app_user.get('nome') or g.app_user.get('telegram_user_id')}"))
            new_id = cur.fetchone()[0]
        conn.commit()
    finally:
        conn.close()

    log_audit(get_db, g.app_user, "miniapp:silenciar",
              target_type="maintenance", target_id=new_id,
              detail={"minutos": minutos, "motivo": motivo})
    return jsonify({"ok": True, "id": new_id, "minutos": minutos})


@app.route("/api/manutencoes/<int:mid>/encerrar", methods=["POST"])
@require_telegram_auth
def api_manutencoes_encerrar(mid):
    from flask import g
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE maintenance_window SET fim=NOW() WHERE id=%s AND fim > NOW()",
                        (mid,))
            affected = cur.rowcount
        conn.commit()
    finally:
        conn.close()

    if affected == 0:
        return jsonify({"ok": False, "msg": "janela não encontrada ou já expirada"}), 404
    log_audit(get_db, g.app_user, "miniapp:silenciar_encerrar",
              target_type="maintenance", target_id=mid)
    return jsonify({"ok": True})


# ===========================================================================
# FASE D — Diagnóstico de CPE e MikroTik
# ===========================================================================

def _mt_connect(nas_id):
    """Conecta no MikroTik pelo id. Retorna (api, secret)."""
    if not MIKROTIK_AVAILABLE:
        raise RuntimeError("librouteros indisponível")
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM nas WHERE id=%s", (nas_id,))
            nas = cur.fetchone()
    finally:
        conn.close()
    if not nas:
        raise RuntimeError("NAS não encontrado")
    if not nas.get("mikrotik_user") or not nas.get("mikrotik_pass"):
        raise RuntimeError("NAS sem credenciais")
    api = librouteros.connect(
        host=nas["nasname"],
        username=nas["mikrotik_user"],
        password=nas["mikrotik_pass"],
        port=int(nas.get("mikrotik_port") or 8728),
        timeout=10,
    )
    return api, nas["secret"]


@app.route("/api/nas/<int:nas_id>/ping")
@require_telegram_auth
def api_nas_ping(nas_id):
    host = (request.args.get("host") or "8.8.8.8").strip()
    count = min(int(request.args.get("count") or 4), 10)
    try:
        api, _ = _mt_connect(nas_id)
        try:
            r = list(api("/ping", **{"address": host, "count": str(count)}))
        finally:
            try: api.close()
            except Exception: pass
        return jsonify({"ok": True, "host": host, "result": r})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/nas/<int:nas_id>/traceroute")
@require_telegram_auth
def api_nas_traceroute(nas_id):
    host = (request.args.get("host") or "8.8.8.8").strip()
    try:
        api, _ = _mt_connect(nas_id)
        try:
            r = list(api("/tool/traceroute", **{"address": host, "count": "1"}))
        finally:
            try: api.close()
            except Exception: pass
        return jsonify({"ok": True, "host": host, "hops": r[:30]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/nas/<int:nas_id>/dns")
@require_telegram_auth
def api_nas_dns(nas_id):
    nome = (request.args.get("nome") or "google.com").strip()
    try:
        api, _ = _mt_connect(nas_id)
        try:
            r = list(api("/ip/dns/cache/print"))
        finally:
            try: api.close()
            except Exception: pass
        matches = [x for x in r if nome.lower() in (x.get("name") or "").lower()][:20]
        return jsonify({"ok": True, "nome": nome, "registros": matches})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ---------- CPE diagnóstico (via GenieACS) ----------

def _gv(raw, path):
    parts = path.split(".")
    cur = raw
    for p in parts:
        if not isinstance(cur, dict): return None
        cur = cur.get(p)
    if isinstance(cur, dict): return cur.get("_value")
    return cur


@app.route("/api/cpe/<int:cpe_id>/hosts")
@require_telegram_auth
def api_cpe_hosts(cpe_id):
    """Lista hosts conectados na LAN do CPE (via TR-098 e TR-181)."""
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT genieacs_id FROM cpe_devices WHERE id=%s", (cpe_id,))
            cpe = cur.fetchone()
    finally:
        conn.close()
    if not cpe or not cpe.get("genieacs_id"):
        return jsonify({"error": "CPE sem genieacs_id"}), 404

    try:
        r = requests.get(
            f"{GENIEACS_NBI_URL}/devices",
            params={"query": json.dumps({"_id": cpe["genieacs_id"]})},
            timeout=8,
        )
        if not r.ok:
            return jsonify({"error": "GenieACS retornou " + str(r.status_code)}), 502
        devs = r.json()
        if not devs:
            return jsonify({"hosts": []})
        raw = devs[0]
    except Exception as e:
        return jsonify({"error": str(e)}), 502

    hosts = []
    # TR-098
    try:
        host_root = (raw.get("InternetGatewayDevice", {})
                       .get("LANDevice", {}).get("1", {})
                       .get("Hosts", {}).get("Host", {}))
        for idx, h in host_root.items():
            if not idx.isdigit() or not isinstance(h, dict): continue
            ip  = (h.get("IPAddress")  or {}).get("_value") if isinstance(h.get("IPAddress"),  dict) else (h.get("IPAddress")  or "")
            mac = (h.get("MACAddress") or {}).get("_value") if isinstance(h.get("MACAddress"), dict) else (h.get("MACAddress") or "")
            if not ip and not mac: continue
            name = (h.get("HostName") or {}).get("_value") if isinstance(h.get("HostName"), dict) else (h.get("HostName") or "*")
            active = (h.get("Active") or {}).get("_value") if isinstance(h.get("Active"), dict) else h.get("Active")
            hosts.append({"hostname": name, "ip": ip, "mac": (mac or "").upper(), "active": bool(active)})
    except Exception:
        pass
    # TR-181 fallback
    if not hosts:
        try:
            host_root = raw.get("Device", {}).get("Hosts", {}).get("Host", {})
            for idx, h in host_root.items():
                if not idx.isdigit() or not isinstance(h, dict): continue
                ip  = (h.get("IPAddress") or {}).get("_value") if isinstance(h.get("IPAddress"), dict) else (h.get("IPAddress") or "")
                mac = (h.get("PhysAddress") or {}).get("_value") if isinstance(h.get("PhysAddress"), dict) else (h.get("PhysAddress") or "")
                if not ip and not mac: continue
                name = (h.get("HostName") or {}).get("_value") if isinstance(h.get("HostName"), dict) else (h.get("HostName") or "*")
                active = (h.get("Active") or {}).get("_value") if isinstance(h.get("Active"), dict) else h.get("Active")
                hosts.append({"hostname": name, "ip": ip, "mac": (mac or "").upper(), "active": bool(active)})
        except Exception:
            pass
    return jsonify({"hosts": hosts, "total": len(hosts)})


@app.route("/api/cpe/<int:cpe_id>/wifi", methods=["GET", "POST"])
@require_telegram_auth
def api_cpe_wifi(cpe_id):
    """GET: lê SSID/senha atuais (do banco). POST: atualiza via GenieACS."""
    from flask import g
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT genieacs_id, ssid, ssid_5g, ssid_24g FROM cpe_devices WHERE id=%s", (cpe_id,))
            cpe = cur.fetchone()
    finally:
        conn.close()
    if not cpe or not cpe.get("genieacs_id"):
        return jsonify({"error": "CPE sem genieacs_id"}), 404

    if request.method == "GET":
        return jsonify({"ssid": cpe.get("ssid"), "ssid_24g": cpe.get("ssid_24g"), "ssid_5g": cpe.get("ssid_5g")})

    body = request.get_json(silent=True) or {}
    ssid_24g = (body.get("ssid_24g") or "").strip()
    ssid_5g  = (body.get("ssid_5g") or "").strip()
    senha_24g = (body.get("senha_24g") or "").strip()
    senha_5g  = (body.get("senha_5g") or "").strip()

    log_audit(get_db, g.app_user, "miniapp:cpe_wifi",
              target_type="cpe", target_id=cpe_id,
              detail={"ssid_24g": ssid_24g, "ssid_5g": ssid_5g, "trocou_senha_24g": bool(senha_24g), "trocou_senha_5g": bool(senha_5g)})

    # Tenta TR-098 (mais comum em ONUs brasileiras)
    pvs = []
    if ssid_24g: pvs.append(["InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID", ssid_24g, "xsd:string"])
    if senha_24g: pvs.append(["InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase", senha_24g, "xsd:string"])
    if ssid_5g:  pvs.append(["InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.SSID", ssid_5g, "xsd:string"])
    if senha_5g: pvs.append(["InternetGatewayDevice.LANDevice.1.WLANConfiguration.5.KeyPassphrase", senha_5g, "xsd:string"])

    if not pvs:
        return jsonify({"error": "informe ao menos um campo"}), 400

    encoded = urllib.parse.quote(cpe["genieacs_id"], safe="")
    try:
        r = requests.post(
            f"{GENIEACS_NBI_URL}/devices/{encoded}/tasks?timeout=15000&connection_request",
            json={"name": "setParameterValues", "parameterValues": pvs},
            timeout=20,
        )
        if r.ok:
            return jsonify({"ok": True, "msg": "WiFi atualizado", "params_set": len(pvs)})
        return jsonify({"ok": False, "msg": f"GenieACS {r.status_code}", "detail": r.text[:300]}), 502
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)}), 502


# ---------- Live events (audit + alertas) ----------

@app.route("/api/live/events")
@require_telegram_auth
def api_live_events():
    """Últimos N eventos do audit_log + alertas firing recentes."""
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT 'audit' AS source, ts, action AS event,
                       usuario_nome AS who, ip,
                       target_type, target_id, detail
                  FROM audit_log
                 WHERE ts > NOW() - INTERVAL '1 hour'
              ORDER BY ts DESC
                 LIMIT 50
            """)
            audits = [dict(r) for r in cur.fetchall()]
            cur.execute("""
                SELECT 'alert' AS source, last_sent_at AS ts,
                       event_type AS event, dedup_key AS who,
                       severity, firing, last_msg
                  FROM alert_state
                 WHERE last_sent_at > NOW() - INTERVAL '1 hour'
              ORDER BY last_sent_at DESC
                 LIMIT 50
            """)
            alerts = [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

    events = []
    for a in audits + alerts:
        for k in ("ts",):
            if a.get(k):
                a[k] = str(a[k])
        events.append(a)
    events.sort(key=lambda x: x.get("ts", ""), reverse=True)
    return jsonify({"events": events[:80]})


# ===========================================================================
# FASE E — Alertas, Auditoria, Relatórios
# ===========================================================================

@app.route("/api/alertas")
@require_telegram_auth
def api_alertas():
    """Lista alertas firing + recentemente resolvidos."""
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT dedup_key, event_type, severity, firing,
                       primeira_vez, ultima_vez, last_sent_at,
                       last_msg, count_total
                  FROM alert_state
                 WHERE firing = TRUE
                    OR ultima_vez > NOW() - INTERVAL '6 hours'
              ORDER BY firing DESC,
                       CASE severity
                         WHEN 'critical' THEN 1
                         WHEN 'warning'  THEN 2
                         ELSE 3
                       END,
                       last_sent_at DESC
                 LIMIT 100
            """)
            rows = cur.fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(r)
        for k in ("primeira_vez", "ultima_vez", "last_sent_at"):
            if d.get(k):
                d[k] = str(d[k])
        out.append(d)
    return jsonify({"alertas": out})


@app.route("/api/alertas/<path:dedup_key>/resolver", methods=["POST"])
@require_telegram_auth
def api_alerta_resolver(dedup_key):
    from flask import g
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE alert_state SET firing = FALSE, ultima_vez = NOW()
                 WHERE dedup_key = %s AND firing = TRUE
            """, (dedup_key,))
            affected = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    if affected == 0:
        return jsonify({"ok": False, "msg": "alerta não encontrado ou já resolvido"}), 404
    log_audit(get_db, g.app_user, "miniapp:alerta_resolver",
              target_type="alert", target_id=dedup_key)
    return jsonify({"ok": True})


@app.route("/api/audit")
@require_telegram_auth
def api_audit():
    action = (request.args.get("action") or "").strip()
    user   = (request.args.get("user") or "").strip()
    days   = max(int(request.args.get("days") or 7), 1)

    where = ["ts > NOW() - (%s * INTERVAL '1 day')"]
    params = [days]
    if action:
        where.append("action ILIKE %s"); params.append(f"%{action}%")
    if user:
        where.append("usuario_nome ILIKE %s"); params.append(f"%{user}%")

    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"""
                SELECT id, ts, usuario_nome, ip, action,
                       target_type, target_id, detail
                  FROM audit_log
                 WHERE {' AND '.join(where)}
              ORDER BY ts DESC
                 LIMIT 200
            """, params)
            rows = cur.fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(r)
        if d.get("ts"): d["ts"] = str(d["ts"])
        out.append(d)
    return jsonify({"audit": out, "total": len(out)})


@app.route("/api/relatorios/top_consumo")
@require_telegram_auth
def api_rel_top_consumo():
    horas = min(int(request.args.get("horas") or 24), 168)
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT COALESCE(c.nome, ra.username) AS nome, ra.username,
                       SUM(COALESCE(ra.acctinputoctets,0) + COALESCE(ra.acctoutputoctets,0))::bigint AS bytes,
                       COUNT(DISTINCT ra.acctsessionid) AS sessoes
                  FROM radacct ra
                  LEFT JOIN clientes c ON c.pppoe_login = ra.username
                 WHERE COALESCE(ra.acctupdatetime, ra.acctstarttime) > NOW() - (%s * INTERVAL '1 hour')
              GROUP BY c.nome, ra.username
              ORDER BY bytes DESC
                 LIMIT 10
            """, (horas,))
            rows = cur.fetchall()
    finally:
        conn.close()
    return jsonify({"top": [dict(r) for r in rows], "horas": horas})


@app.route("/api/relatorios/sessoes_hora")
@require_telegram_auth
def api_rel_sessoes_hora():
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT date_trunc('hour', acctstarttime) AS hora,
                       COUNT(DISTINCT acctsessionid) AS sessoes,
                       COUNT(DISTINCT username) AS usuarios
                  FROM radacct
                 WHERE acctstarttime > NOW() - INTERVAL '24 hours'
              GROUP BY hora
              ORDER BY hora
            """)
            rows = cur.fetchall()
    finally:
        conn.close()
    return jsonify({"data": [{"hora": str(r["hora"]), "sessoes": int(r["sessoes"]), "usuarios": int(r["usuarios"])} for r in rows]})


@app.route("/api/relatorios/mttr")
@require_telegram_auth
def api_rel_mttr():
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT
                  date_trunc('day', resolvido_em)::date AS dia,
                  COUNT(*) AS resolvidos,
                  EXTRACT(EPOCH FROM AVG(resolvido_em - criado_em))/60 AS mttr_min
                FROM chamados
                WHERE status='resolvido'
                  AND resolvido_em > NOW() - INTERVAL '7 days'
                GROUP BY dia
                ORDER BY dia
            """)
            rows = cur.fetchall()
    finally:
        conn.close()
    return jsonify({"data": [{"dia": str(r["dia"]), "resolvidos": int(r["resolvidos"]), "mttr_min": float(r["mttr_min"] or 0)} for r in rows]})


# ===========================================================================
# FASE F — CRUD de Cliente + Importação SGP
# ===========================================================================

SGP_URL = os.environ.get("SGP_URL", "https://linknetam.sgp.net.br/api/ura/consultacliente/")
SGP_TOKEN = os.environ.get("SGP_TOKEN", "")
SGP_APP = os.environ.get("SGP_APP", "APP")


def _consultar_sgp(cpf: str):
    if not SGP_TOKEN:
        return None
    try:
        r = requests.post(
            SGP_URL,
            data={"token": SGP_TOKEN, "app": SGP_APP, "cpfcnpj": cpf},
            timeout=10,
        )
        r.raise_for_status()
        data = r.json()
        contratos = data.get("contratos", [])
        return contratos[0] if contratos else None
    except Exception:
        return None


@app.route("/api/sgp/consultar/<cpf>")
@require_telegram_auth
def api_sgp_consultar(cpf):
    cpf_limpo = re.sub(r"\D", "", cpf)
    if len(cpf_limpo) != 11:
        return jsonify({"error": "CPF deve ter 11 dígitos"}), 400
    contrato = _consultar_sgp(cpf_limpo)
    if not contrato:
        return jsonify({"found": False})
    return jsonify({
        "found": True,
        "nome":            contrato.get("contratoNome"),
        "pppoe_login":     contrato.get("contratoCentralLogin"),
        "status_display":  contrato.get("contratoStatusDisplay"),
        "ip":              contrato.get("servico_ip"),
        "plano":           contrato.get("contratoPlanoInternet"),
    })


@app.route("/api/clientes", methods=["POST"])
@require_telegram_auth
def api_cliente_criar():
    from flask import g
    body = request.get_json(silent=True) or {}
    nome = (body.get("nome") or "").strip()
    cpf  = re.sub(r"\D", "", body.get("cpf") or "")
    plano_id = body.get("plano_id")
    pppoe_login = (body.get("pppoe_login") or "").strip() or None
    ip = (body.get("ip") or "").strip() or None

    if not nome or len(cpf) != 11 or not plano_id:
        return jsonify({"error": "nome, cpf (11 dígitos) e plano_id obrigatórios"}), 400

    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM planos WHERE id=%s", (plano_id,))
            plano = cur.fetchone()
            if not plano:
                return jsonify({"error": "plano_id inválido"}), 400
            try:
                cur.execute("""
                    INSERT INTO clientes (nome, cpf, ip, plano, velocidade_down, velocidade_up,
                                          plano_id, pppoe_login, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'pendente')
                    RETURNING id
                """, (nome, cpf, ip, plano["nome"], plano["velocidade_down"], plano["velocidade_up"],
                      plano_id, pppoe_login))
                new_id = cur.fetchone()["id"]
            except psycopg2.errors.UniqueViolation:
                conn.rollback()
                return jsonify({"error": "CPF já cadastrado"}), 409
            conn.commit()
    finally:
        conn.close()

    log_audit(get_db, g.app_user, "miniapp:cliente_criar",
              target_type="cliente", target_id=new_id,
              detail={"nome": nome, "cpf": cpf, "pppoe_login": pppoe_login})
    return jsonify({"ok": True, "id": new_id})


@app.route("/api/clientes/<int:cliente_id>", methods=["PUT"])
@require_telegram_auth
def api_cliente_editar(cliente_id):
    from flask import g
    body = request.get_json(silent=True) or {}
    fields = []
    params = []
    for k in ("nome", "ip", "pppoe_login", "status"):
        if k in body:
            fields.append(f"{k} = %s")
            params.append((body[k] or "").strip() or None)
    if "plano_id" in body and body["plano_id"]:
        plano_id = int(body["plano_id"])
        conn = get_db()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM planos WHERE id=%s", (plano_id,))
                plano = cur.fetchone()
        finally:
            conn.close()
        if not plano:
            return jsonify({"error": "plano_id inválido"}), 400
        fields += ["plano_id=%s", "plano=%s", "velocidade_down=%s", "velocidade_up=%s"]
        params += [plano_id, plano["nome"], plano["velocidade_down"], plano["velocidade_up"]]

    if not fields:
        return jsonify({"error": "nada a alterar"}), 400

    fields.append("atualizado_em = NOW()")
    params.append(cliente_id)

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE clientes SET {', '.join(fields)} WHERE id=%s", params)
            affected = cur.rowcount
        conn.commit()
    finally:
        conn.close()

    if affected == 0:
        return jsonify({"error": "cliente não encontrado"}), 404
    log_audit(get_db, g.app_user, "miniapp:cliente_editar",
              target_type="cliente", target_id=cliente_id, detail=body)
    return jsonify({"ok": True})


# ===========================================================================
# FASE G — Gestão de infraestrutura (NAS, Pools, Planos, Usuários, API Keys)
# ===========================================================================

# ---------- Planos ----------

@app.route("/api/admin/planos", methods=["GET", "POST"])
@require_telegram_auth
def api_admin_planos():
    from flask import g
    if request.method == "GET":
        conn = get_db()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM planos ORDER BY nome")
                rows = cur.fetchall()
        finally:
            conn.close()
        return jsonify({"planos": [dict(r) for r in rows]})

    body = request.get_json(silent=True) or {}
    nome = (body.get("nome") or "").strip()
    down = int(body.get("velocidade_down") or 0)
    up   = int(body.get("velocidade_up") or 0)
    if not nome or down < 1 or up < 1:
        return jsonify({"error": "nome + velocidades obrigatórios"}), 400
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO planos (nome, velocidade_down, velocidade_up) VALUES (%s,%s,%s) RETURNING id",
                        (nome, down, up))
            new_id = cur.fetchone()[0]
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback(); conn.close()
        return jsonify({"error": "plano com este nome já existe"}), 409
    finally:
        try: conn.close()
        except Exception: pass
    log_audit(get_db, g.app_user, "miniapp:plano_criar",
              target_type="plano", target_id=new_id, detail={"nome": nome})
    return jsonify({"ok": True, "id": new_id})


@app.route("/api/admin/planos/<int:plano_id>", methods=["DELETE"])
@require_telegram_auth
def api_admin_plano_del(plano_id):
    from flask import g
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM planos WHERE id=%s", (plano_id,))
            affected = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    if affected == 0:
        return jsonify({"error": "não encontrado"}), 404
    log_audit(get_db, g.app_user, "miniapp:plano_delete",
              target_type="plano", target_id=plano_id)
    return jsonify({"ok": True})


# ---------- Pools ----------

@app.route("/api/admin/pools", methods=["GET", "POST"])
@require_telegram_auth
def api_admin_pools():
    from flask import g
    if request.method == "GET":
        conn = get_db()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM pools ORDER BY nome")
                rows = cur.fetchall()
        finally:
            conn.close()
        return jsonify({"pools": [dict(r) for r in rows]})

    body = request.get_json(silent=True) or {}
    nome = (body.get("nome") or "").strip()
    ini  = (body.get("range_inicio") or "").strip()
    fim  = (body.get("range_fim") or "").strip()
    desc = (body.get("descricao") or "").strip()
    if not nome or not ini or not fim:
        return jsonify({"error": "nome + range obrigatórios"}), 400
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO pools (nome, range_inicio, range_fim, descricao) VALUES (%s,%s,%s,%s) RETURNING id",
                        (nome, ini, fim, desc))
            new_id = cur.fetchone()[0]
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback(); conn.close()
        return jsonify({"error": "pool com este nome já existe"}), 409
    finally:
        try: conn.close()
        except Exception: pass
    log_audit(get_db, g.app_user, "miniapp:pool_criar",
              target_type="pool", target_id=new_id, detail={"nome": nome})
    return jsonify({"ok": True, "id": new_id})


@app.route("/api/admin/pools/<int:pool_id>", methods=["DELETE"])
@require_telegram_auth
def api_admin_pool_del(pool_id):
    from flask import g
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM pools WHERE id=%s", (pool_id,))
            affected = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    if affected == 0:
        return jsonify({"error": "não encontrado"}), 404
    log_audit(get_db, g.app_user, "miniapp:pool_delete",
              target_type="pool", target_id=pool_id)
    return jsonify({"ok": True})


# ---------- NAS admin ----------

@app.route("/api/admin/nas", methods=["GET", "POST"])
@require_telegram_auth
def api_admin_nas():
    from flask import g
    if request.method == "GET":
        conn = get_db()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT id, nasname, shortname, secret, description, mikrotik_user, mikrotik_port FROM nas ORDER BY id")
                rows = cur.fetchall()
        finally:
            conn.close()
        return jsonify({"nas": [dict(r) for r in rows]})

    body = request.get_json(silent=True) or {}
    nasname   = (body.get("nasname") or "").strip()
    shortname = (body.get("shortname") or "").strip()
    secret    = (body.get("secret") or "").strip()
    desc      = (body.get("description") or "MikroTik").strip()
    mt_user   = (body.get("mikrotik_user") or "admin").strip()
    mt_pass   = (body.get("mikrotik_pass") or "").strip()
    mt_port   = int(body.get("mikrotik_port") or 8728)

    if not nasname or not secret:
        return jsonify({"error": "nasname + secret obrigatórios"}), 400

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO nas (nasname, shortname, secret, description, mikrotik_user, mikrotik_pass, mikrotik_port)
                VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING id
            """, (nasname, shortname, secret, desc, mt_user, mt_pass, mt_port))
            new_id = cur.fetchone()[0]
        conn.commit()
    finally:
        conn.close()
    log_audit(get_db, g.app_user, "miniapp:nas_criar",
              target_type="nas", target_id=new_id, detail={"nasname": nasname})
    return jsonify({"ok": True, "id": new_id})


@app.route("/api/admin/nas/<int:nas_id>", methods=["PUT", "DELETE"])
@require_telegram_auth
def api_admin_nas_one(nas_id):
    from flask import g
    if request.method == "DELETE":
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM nas WHERE id=%s", (nas_id,))
                affected = cur.rowcount
            conn.commit()
        finally:
            conn.close()
        if affected == 0:
            return jsonify({"error": "não encontrado"}), 404
        log_audit(get_db, g.app_user, "miniapp:nas_delete",
                  target_type="nas", target_id=nas_id)
        return jsonify({"ok": True})

    body = request.get_json(silent=True) or {}
    fields, params = [], []
    for k in ("nasname", "shortname", "secret", "description", "mikrotik_user", "mikrotik_pass"):
        if k in body:
            fields.append(f"{k}=%s"); params.append((body[k] or "").strip())
    if "mikrotik_port" in body:
        fields.append("mikrotik_port=%s"); params.append(int(body["mikrotik_port"] or 8728))
    if not fields:
        return jsonify({"error": "nada a alterar"}), 400
    params.append(nas_id)
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE nas SET {', '.join(fields)} WHERE id=%s", params)
            affected = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    if affected == 0:
        return jsonify({"error": "não encontrado"}), 404
    log_audit(get_db, g.app_user, "miniapp:nas_editar",
              target_type="nas", target_id=nas_id, detail=body)
    return jsonify({"ok": True})


# ---------- Usuários do painel ----------

@app.route("/api/admin/usuarios", methods=["GET", "POST"])
@require_telegram_auth
def api_admin_usuarios():
    from flask import g
    if request.method == "GET":
        conn = get_db()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT id, username, role, ativo, criado_em, ultimo_acesso FROM usuarios ORDER BY username")
                rows = cur.fetchall()
        finally:
            conn.close()
        out = []
        for r in rows:
            d = dict(r)
            for k in ("criado_em", "ultimo_acesso"):
                if d.get(k): d[k] = str(d[k])
            out.append(d)
        return jsonify({"usuarios": out})

    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    senha = (body.get("senha") or "").strip()
    role = (body.get("role") or "admin").strip()
    if not username or len(senha) < 6:
        return jsonify({"error": "username + senha (≥6 chars) obrigatórios"}), 400
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO usuarios (username, senha_hash, role) VALUES (%s, %s, %s) RETURNING id",
                        (username, generate_password_hash(senha), role))
            new_id = cur.fetchone()[0]
        conn.commit()
    except psycopg2.errors.UniqueViolation:
        conn.rollback(); conn.close()
        return jsonify({"error": "username já existe"}), 409
    finally:
        try: conn.close()
        except Exception: pass
    log_audit(get_db, g.app_user, "miniapp:usuario_criar",
              target_type="usuario", target_id=new_id, detail={"username": username, "role": role})
    return jsonify({"ok": True, "id": new_id})


@app.route("/api/admin/usuarios/<int:uid>", methods=["DELETE"])
@require_telegram_auth
def api_admin_usuario_del(uid):
    from flask import g
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM usuarios WHERE id=%s", (uid,))
            affected = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    if affected == 0:
        return jsonify({"error": "não encontrado"}), 404
    log_audit(get_db, g.app_user, "miniapp:usuario_delete",
              target_type="usuario", target_id=uid)
    return jsonify({"ok": True})


@app.route("/api/admin/usuarios/<int:uid>/senha", methods=["POST"])
@require_telegram_auth
def api_admin_usuario_senha(uid):
    from flask import g
    body = request.get_json(silent=True) or {}
    senha = (body.get("senha") or "").strip()
    if len(senha) < 6:
        return jsonify({"error": "senha mínimo 6 chars"}), 400
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE usuarios SET senha_hash=%s WHERE id=%s",
                        (generate_password_hash(senha), uid))
            affected = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    if affected == 0:
        return jsonify({"error": "não encontrado"}), 404
    log_audit(get_db, g.app_user, "miniapp:usuario_senha",
              target_type="usuario", target_id=uid)
    return jsonify({"ok": True})


# ---------- API Keys ----------

@app.route("/api/admin/apikeys", methods=["GET", "POST"])
@require_telegram_auth
def api_admin_apikeys():
    from flask import g
    if request.method == "GET":
        conn = get_db()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT k.id, k.nome, k.ativo, k.criado_em, k.ultimo_uso,
                           (SELECT COUNT(*) FROM api_key_ips i WHERE i.api_key_id = k.id) AS ips_distintos
                      FROM api_keys k ORDER BY k.id
                """)
                rows = cur.fetchall()
        finally:
            conn.close()
        out = []
        for r in rows:
            d = dict(r)
            for k in ("criado_em", "ultimo_uso"):
                if d.get(k): d[k] = str(d[k])
            out.append(d)
        return jsonify({"apikeys": out})

    body = request.get_json(silent=True) or {}
    nome = (body.get("nome") or "").strip()
    if not nome:
        return jsonify({"error": "nome obrigatório"}), 400

    raw_key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO api_keys (nome, key_hash) VALUES (%s, %s) RETURNING id",
                        (nome, key_hash))
            new_id = cur.fetchone()[0]
        conn.commit()
    finally:
        conn.close()
    log_audit(get_db, g.app_user, "miniapp:apikey_criar",
              target_type="apikey", target_id=new_id, detail={"nome": nome})
    return jsonify({"ok": True, "id": new_id, "key": raw_key,
                    "msg": "Guarde esta key — ela só aparece UMA vez"})


@app.route("/api/admin/apikeys/<int:kid>", methods=["DELETE"])
@require_telegram_auth
def api_admin_apikey_del(kid):
    from flask import g
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM api_keys WHERE id=%s", (kid,))
            affected = cur.rowcount
        conn.commit()
    finally:
        conn.close()
    if affected == 0:
        return jsonify({"error": "não encontrado"}), 404
    log_audit(get_db, g.app_user, "miniapp:apikey_delete",
              target_type="apikey", target_id=kid)
    return jsonify({"ok": True})


@app.route("/api/admin/apikeys/<int:kid>/ips")
@require_telegram_auth
def api_admin_apikey_ips(kid):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT ip, primeira_vez, ultima_vez
                  FROM api_key_ips WHERE api_key_id=%s
              ORDER BY ultima_vez DESC LIMIT 50
            """, (kid,))
            rows = cur.fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        d = dict(r)
        for k in ("primeira_vez", "ultima_vez"):
            if d.get(k): d[k] = str(d[k])
        out.append(d)
    return jsonify({"ips": out})


# ===========================================================================
# FASE L/M/O — Recursos avançados de IA
# ===========================================================================

from ai_features import (
    ai_search, ai_briefing,
    transcribe_audio, structure_dictation,
    generate_release_notes,
)
import hmac
import hashlib as _hashlib


@app.route("/api/ai/search", methods=["POST"])
@require_telegram_auth
def api_ai_search():
    body = request.get_json(silent=True) or {}
    pergunta = (body.get("q") or "").strip()
    if not pergunta:
        return jsonify({"error": "campo 'q' obrigatório"}), 400
    result = ai_search(get_db, pergunta)
    return jsonify(result)


@app.route("/api/ai/briefing")
@require_telegram_auth
def api_ai_briefing():
    from flask import g
    force = request.args.get("force") == "1"
    text = ai_briefing(get_db, g.app_user.get("telegram_user_id"), force=force)
    return jsonify({"briefing": text})


@app.route("/api/ai/transcribe", methods=["POST"])
@require_telegram_auth
def api_ai_transcribe():
    """Recebe áudio multipart + lista opcional de campos pra estruturar."""
    if "audio" not in request.files:
        return jsonify({"error": "campo 'audio' obrigatório"}), 400
    audio = request.files["audio"].read()
    if not audio:
        return jsonify({"error": "áudio vazio"}), 400
    fields_json = request.form.get("fields", "")
    text = transcribe_audio(audio)
    if not text:
        return jsonify({"error": "transcrição falhou (verifique OPENAI_API_KEY)"}), 502
    structured = {}
    if fields_json:
        try:
            fields = json.loads(fields_json)
            structured = structure_dictation(text, fields)
        except Exception:
            pass
    return jsonify({"text": text, "structured": structured})


# ===========================================================================
# FASE P — Webhook GitHub para release notes
# ===========================================================================

def _verify_github_signature(payload_bytes, signature_header):
    """Verifica HMAC-SHA256 do GitHub webhook."""
    secret = ""
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT valor FROM alertas_config WHERE chave='github_webhook_secret'")
            row = cur.fetchone()
            secret = row[0] if row else ""
        conn.close()
    except Exception:
        pass
    if not secret or not signature_header:
        return False
    if not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        secret.encode(), payload_bytes, _hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


@app.route("/api/webhooks/github", methods=["POST"])
def api_webhook_github():
    """
    Recebe push events do GitHub. Sem auth Telegram (vem do GitHub direto).
    Valida HMAC com 'github_webhook_secret' em alertas_config.
    """
    sig = request.headers.get("X-Hub-Signature-256", "")
    if not _verify_github_signature(request.data, sig):
        log.warning("webhook github: assinatura HMAC inválida")
        return jsonify({"error": "assinatura inválida"}), 401

    event = request.headers.get("X-GitHub-Event", "")
    if event != "push":
        log.info("webhook github: evento ignorado (%s)", event)
        return jsonify({"ignored": True, "event": event})

    payload = request.get_json(silent=True) or {}
    commits = payload.get("commits", [])
    pusher = payload.get("pusher", {}).get("name", "?")
    branch = payload.get("ref", "").replace("refs/heads/", "")
    repo_name = payload.get("repository", {}).get("name", "?")

    log.info("webhook github: push em %s/%s por %s, %d commits",
             repo_name, branch, pusher, len(commits))

    # Ignora pushes pra branches que não main
    if branch not in ("main", "master"):
        log.info("webhook github: branch %s ignorada", branch)
        return jsonify({"ignored": True, "branch": branch})

    # Filtra commits ignorando merges
    real_commits = [c for c in commits if not c.get("message", "").startswith("Merge")]
    if not real_commits:
        log.info("webhook github: só merges, ignorando")
        return jsonify({"ignored": True, "reason": "só merges"})

    # Lista resumida pra log + fallback
    commit_list = "\n".join(
        f"• {c.get('message', '').splitlines()[0][:80]}" for c in real_commits[:10]
    )

    # Gera release note via IA
    notes = generate_release_notes(real_commits)
    log.info("webhook github: IA gerou %d chars", len(notes or ""))

    # Fallback: se IA achou irrelevante, manda mensagem técnica mínima
    if not notes or not notes.strip():
        notes = (
            f"<i>Sem mudanças de impacto direto pro cliente final.</i>\n\n"
            f"<b>Commits:</b>\n{commit_list}"
        )

    # Posta no Telegram
    from notifier import TelegramNotifier
    notifier = TelegramNotifier(get_db)
    msg = (
        f"<b>🚀 Atualização do sistema</b>\n"
        f"<i>{repo_name} · {pusher} · {len(real_commits)} commit(s)</i>\n\n"
        f"{notes}"
    )
    sent = notifier.send("release_note", msg, severity="info", cooldown=0, force=False)
    log.info("webhook github: notifier.send retornou %s", sent)
    return jsonify({"ok": True, "commits": len(real_commits), "sent": sent})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
