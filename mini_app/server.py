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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
