import os
import re
import csv
import io
import json
import time
import hashlib
import secrets
import subprocess
import ipaddress
import logging
from datetime import datetime, timezone
import requests
import psycopg2
import psycopg2.extras
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, jsonify, session, Response, stream_with_context,
)
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------------------------------------------------------
# JSON structured logging
# ---------------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            log_obj["exc"] = self.formatException(record.exc_info)
        return json.dumps(log_obj, ensure_ascii=False)

_handler = logging.StreamHandler()
_handler.setFormatter(JsonFormatter())
logging.basicConfig(level=logging.INFO, handlers=[_handler])
log = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")

@app.template_global()
def fmtUptime(sec):
    sec = int(sec or 0)
    d = sec // 86400; h = (sec % 86400) // 3600; m = (sec % 3600) // 60
    if d: return f"{d}d {h}h {m}m"
    if h: return f"{h}h {m}m"
    return f"{m}m"

try:
    import librouteros
    MIKROTIK_AVAILABLE = True
except ImportError:
    MIKROTIK_AVAILABLE = False

# ---------------------------------------------------------------------------
# GenieACS — cliente da NBI REST API
# ---------------------------------------------------------------------------

class GenieACSClient:
    """Encapsula chamadas à GenieACS NBI (porta 7557)."""

    def __init__(self):
        self.base = os.environ.get("GENIEACS_NBI_URL", "http://genieacs-nbi:7557").rstrip("/")
        self.timeout = 8

    def _get(self, path, params=None):
        r = requests.get(f"{self.base}{path}", params=params, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _post(self, path, data):
        r = requests.post(f"{self.base}{path}", json=data, timeout=self.timeout)
        r.raise_for_status()
        try:
            return r.json()
        except Exception:
            return {}

    def _delete(self, path):
        r = requests.delete(f"{self.base}{path}", timeout=self.timeout)
        r.raise_for_status()

    def ping(self):
        """Verifica se GenieACS está acessível."""
        try:
            requests.get(f"{self.base}/devices?limit=1", timeout=3)
            return True
        except Exception:
            return False

    def list_devices(self, query=None, limit=200, skip=0):
        """Lista CPEs. query é dict MongoDB-style, ex: {'_deviceId._SerialNumber': 'ABC'}."""
        params = {"limit": limit, "skip": skip}
        if query:
            params["query"] = json.dumps(query)
        return self._get("/devices", params=params)

    def get_device(self, device_id):
        """Retorna dados completos de um CPE pelo ID GenieACS."""
        import urllib.parse
        encoded = urllib.parse.quote(device_id, safe="")
        devices = self._get(f"/devices", params={"query": json.dumps({"_id": device_id})})
        return devices[0] if devices else None

    def reboot(self, device_id):
        """Envia task de reboot ao CPE."""
        import urllib.parse
        encoded = urllib.parse.quote(device_id, safe="")
        return self._post(f"/devices/{encoded}/tasks?timeout=3000&connection_request", {"name": "reboot"})

    def refresh(self, device_id):
        """Força o CPE a se conectar ao ACS imediatamente."""
        import urllib.parse
        encoded = urllib.parse.quote(device_id, safe="")
        return self._post(f"/devices/{encoded}/tasks?connection_request", {"name": "getParameterValues", "parameterNames": ["Device.DeviceInfo."]})

    def get_param(self, device_id, param_path):
        """Lê um parâmetro TR-069 via task."""
        import urllib.parse
        encoded = urllib.parse.quote(device_id, safe="")
        return self._post(f"/devices/{encoded}/tasks?timeout=10000&connection_request",
                          {"name": "getParameterValues", "parameterNames": [param_path]})

    def set_params(self, device_id, param_values):
        """
        Seta parâmetros TR-069.
        param_values: lista de [path, valor, tipo]
        ex: [["Device.WiFi.SSID.1.SSID", "MeuWifi", "xsd:string"]]
        """
        import urllib.parse
        encoded = urllib.parse.quote(device_id, safe="")
        return self._post(f"/devices/{encoded}/tasks?timeout=15000&connection_request",
                          {"name": "setParameterValues", "parameterValues": param_values})

    def factory_reset(self, device_id):
        """Envia task de reset de fábrica."""
        import urllib.parse
        encoded = urllib.parse.quote(device_id, safe="")
        return self._post(f"/devices/{encoded}/tasks?timeout=3000&connection_request",
                          {"name": "factoryReset"})

    def delete_device(self, device_id):
        """Remove CPE do GenieACS."""
        import urllib.parse
        encoded = urllib.parse.quote(device_id, safe="")
        self._delete(f"/devices/{encoded}")

    def parse_device(self, raw):
        """Extrai os campos mais importantes de um device GenieACS para exibição.
        Suporta TR-181 (Device.*), TR-098 (InternetGatewayDevice.*) e DeviceID.*.
        """
        def gv(obj, *paths, default=None):
            """Navega no JSON do GenieACS {_value, _type, _writable...}."""
            for path in paths:
                parts = path.split(".")
                cur = obj
                for p in parts:
                    if not isinstance(cur, dict):
                        cur = None
                        break
                    cur = cur.get(p)
                if cur is not None:
                    if isinstance(cur, dict) and "_value" in cur:
                        v = cur["_value"]
                        return v if v not in (None, "") else None
                    if not isinstance(cur, dict):
                        return cur
            return default

        def gv_any(obj, *paths, default=None):
            """Igual a gv mas aceita valor vazio como válido."""
            for path in paths:
                parts = path.split(".")
                cur = obj
                for p in parts:
                    if not isinstance(cur, dict):
                        cur = None
                        break
                    cur = cur.get(p)
                if cur is not None:
                    if isinstance(cur, dict) and "_value" in cur:
                        return cur["_value"]
                    if not isinstance(cur, dict):
                        return cur
            return default

        def find_ssid_by_index(obj, idx):
            """Busca SSID em WLANConfiguration.<idx>."""
            return gv(obj,
                f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{idx}.SSID",
                f"Device.WiFi.SSID.{idx}.SSID",
                default=None)

        def find_all_ssids(obj):
            """Varre WLANConfiguration.1-8 e devolve lista de SSIDs não vazios."""
            ssids = []
            igd = obj.get("InternetGatewayDevice", {}).get("LANDevice", {}).get("1", {}).get("WLANConfiguration", {})
            for k, v in igd.items():
                if k.isdigit() and isinstance(v, dict):
                    ssid_node = v.get("SSID", {})
                    val = ssid_node.get("_value", "") if isinstance(ssid_node, dict) else ""
                    if val:
                        ssids.append((int(k), val))
            ssids.sort()
            return ssids

        dev_id  = raw.get("_id", "")
        dev_info = raw.get("_deviceId", {})

        # Uptime: alguns firmwares não expõem
        uptime_raw = gv(raw,
            "InternetGatewayDevice.DeviceInfo.UpTime",
            "Device.DeviceInfo.UpTime",
            default=0)
        try:
            uptime_sec = int(uptime_raw or 0)
        except Exception:
            uptime_sec = 0

        # Fabricante: DeviceID.Manufacturer (Intelbras/Huawei) ou DeviceInfo
        fabricante = (
            gv(raw, "DeviceID.Manufacturer", default=None)
            or dev_info.get("_Manufacturer", "")
            or gv(raw, "InternetGatewayDevice.DeviceInfo.Manufacturer",
                       "Device.DeviceInfo.Manufacturer", default="")
        )

        # Firmware
        firmware = gv(raw,
            "InternetGatewayDevice.DeviceInfo.SoftwareVersion",
            "Device.DeviceInfo.SoftwareVersion",
            default="")

        # IP WAN: PPPoE tem prioridade sobre IP puro
        ip_wan = (
            gv(raw, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress", default=None)
            or gv(raw, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress", default=None)
            or gv(raw, "Device.IP.Interface.1.IPv4Address.1.IPAddress", default="")
        ) or ""

        # MAC WAN: PPPoE → Ethernet WAN → fallback
        mac_wan = (
            gv(raw, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.MACAddress", default=None)
            or gv(raw, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANEthernetInterfaceConfig.MACAddress", default=None)
            or gv(raw, "Device.Ethernet.Interface.1.MACAddress", default="")
        ) or ""

        # IP LAN
        ip_lan = (
            gv(raw, "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.1.IPInterfaceIPAddress", default=None)
            or gv(raw, "Device.LAN.IPAddress", default="")
        ) or ""

        # SSIDs — descobre automaticamente quais índices têm valor
        all_ssids = find_all_ssids(raw)
        # Intelbras AX1800: índice 1 = 5GHz, índice 6 = 2.4GHz
        # Lógica: o SSID de menor índice com valor é o "principal",
        # mas permitimos fallback para índices maiores
        ssid_main  = all_ssids[0][1] if all_ssids else ""
        ssid_other = all_ssids[1][1] if len(all_ssids) > 1 else ""

        # Tenta identificar qual é 2.4 e qual é 5G pelo canal (se disponível)
        # Se não encontrar, usa posição: menor índice = 5G (padrão Intelbras)
        ssid_5g  = ssid_main
        ssid_24g = ssid_other

        # Sinal óptico (ONUs GPON)
        rx_power = (
            gv(raw, "InternetGatewayDevice.WANDevice.1.X_PON_RxPower", default=None)
            or gv(raw, "Device.Optical.Interface.1.CurrentPower", default=None)
        )
        if rx_power is not None:
            try:
                rx_power = float(rx_power)
            except Exception:
                rx_power = None

        # Todos os SSIDs para exibição expandida
        all_ssids_display = [{"idx": s[0], "ssid": s[1]} for s in all_ssids]

        return {
            "genieacs_id":  dev_id,
            "serial":       dev_info.get("_SerialNumber", "") or gv(raw, "InternetGatewayDevice.DeviceInfo.SerialNumber", "Device.DeviceInfo.SerialNumber", default=""),
            "oui":          dev_info.get("_OUI", ""),
            "modelo":       dev_info.get("_ProductClass", "") or gv(raw, "InternetGatewayDevice.DeviceInfo.ModelName", "Device.DeviceInfo.ModelName", default=""),
            "fabricante":   fabricante,
            "firmware":     firmware,
            "ip_wan":       ip_wan,
            "ip_lan":       ip_lan,
            "mac_wan":      mac_wan,
            "ssid":         ssid_5g,
            "ssid_5g":      ssid_5g,
            "ssid_24g":     ssid_24g,
            "all_ssids":    all_ssids_display,
            "rx_power":     rx_power,
            "uptime_sec":   uptime_sec,
            "online":       raw.get("_lastInform") is not None,
            "last_inform":  raw.get("_lastInform", ""),
        }

_genieacs = GenieACSClient()

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


def get_redis():
    try:
        import redis as redis_lib
        r = redis_lib.Redis(
            host=os.environ.get("REDIS_HOST", "redis"),
            port=int(os.environ.get("REDIS_PORT", 6379)),
            decode_responses=True,
            socket_connect_timeout=2,
        )
        r.ping()
        return r
    except Exception:
        return None


def get_online_users() -> set:
    """Retorna set de pppoe_logins ativos.
    Fonte primária: API do MikroTik (todos os NAS com credenciais cadastradas).
    Fallback: radacct local.
    Cache Redis por 60s.
    """
    r = get_redis()
    if r:
        cached = r.get("online_users")
        if cached:
            return set(json.loads(cached))

    online = set()

    # --- Fonte 1: MikroTik API (captura clientes de QUALQUER servidor RADIUS) ---
    if MIKROTIK_AVAILABLE:
        conn = get_db()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT nasname, mikrotik_user, mikrotik_pass, mikrotik_port "
                "FROM nas WHERE mikrotik_user IS NOT NULL AND mikrotik_pass IS NOT NULL "
                "AND mikrotik_pass != ''"
            )
            nas_list = cur.fetchall()
        conn.close()

        for nas in nas_list:
            try:
                api = librouteros.connect(
                    host=nas["nasname"],
                    username=nas["mikrotik_user"],
                    password=nas["mikrotik_pass"],
                    port=int(nas.get("mikrotik_port") or 8728),
                    timeout=5,
                )
                try:
                    sessions = list(api("/ppp/active/print"))
                    for s in sessions:
                        name = s.get("name", "")
                        if name:
                            online.add(name)
                finally:
                    api.close()
            except Exception:
                pass  # NAS inacessível — ignora e continua

    # --- Fallback: radacct local (quando MikroTik não disponível ou sem credenciais) ---
    if not online:
        conn = get_db()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT DISTINCT c.pppoe_login
                FROM clientes c
                INNER JOIN radacct ra ON ra.username = c.pppoe_login
                WHERE ra.acctstoptime IS NULL AND c.pppoe_login IS NOT NULL
            """)
            online = {row["pppoe_login"] for row in cur.fetchall()}
        conn.close()

    if r:
        r.setex("online_users", 60, json.dumps(list(online)))
    return online


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

def upsert_radius_user(conn, login: str, status: str, down: int, up: int, ip: str = "", senha: str = "123"):
    with conn.cursor() as cur:
        cur.execute("DELETE FROM radcheck WHERE username = %s", (login,))
        cur.execute("DELETE FROM radreply WHERE username = %s", (login,))

        if status == "ativo":
            cur.execute(
                "INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, %s, %s, %s)",
                (login, "Cleartext-Password", ":=", senha or "123"),
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
        elif status == "suspenso":
            # Autentica mas recebe IP da faixa bloqueada (10.24.0.0/20)
            # O MikroTik tem regra de firewall bloqueando essa faixa
            cur.execute(
                "INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, %s, %s, %s)",
                (login, "Cleartext-Password", ":=", senha or "123"),
            )
            if ip:
                cur.execute(
                    "INSERT INTO radreply (username, attribute, op, value) VALUES (%s, %s, %s, %s)",
                    (login, "Framed-IP-Address", ":=", ip),
                )
        else:
            # pendente ou qualquer outro status — nega acesso
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


SUSPENSION_NETWORK = ipaddress.ip_network("10.24.0.0/20", strict=False)


def alocar_ip_suspenso(conn) -> str:
    """Retorna um IP livre da faixa 10.24.0.0/20 para clientes suspensos.
    Verifica IPs já em uso no radreply (onde o IP de suspensão fica registrado).
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT value FROM radreply WHERE attribute = 'Framed-IP-Address' AND value LIKE '10.24.%'",
        )
        usados = {row[0] for row in cur.fetchall()}

    hosts = SUSPENSION_NETWORK.hosts()
    next(hosts, None)  # pula 10.24.0.1 (reservado para gateway)
    for ip in hosts:
        addr = str(ip)
        if addr not in usados:
            return addr
    return "10.24.0.2"  # fallback — nunca deve ocorrer num /20 com 4094 hosts


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
    por_pagina = min(int(request.args.get("por_pagina", 50)), 200)
    busca = request.args.get("busca", "").strip()
    filtro_status = request.args.get("status", "").strip()

    offset = (pagina - 1) * por_pagina

    online_users = get_online_users()

    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
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

        # Online apenas entre clientes cadastrados localmente.
        # Isso evita contagem maior que total_clientes quando o MikroTik traz
        # sessões de outros logins/sistemas.
        if online_users:
            placeholders = ",".join(["%s"] * len(online_users))
            cur.execute(
                f"SELECT COUNT(*) AS total FROM clientes WHERE pppoe_login IN ({placeholders})",
                list(online_users),
            )
            total_online_cadastrados = cur.fetchone()["total"]
        else:
            total_online_cadastrados = 0

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
        "total_online": total_online_cadastrados,
        "total_offline": max(0, total_clientes - total_online_cadastrados),
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
        except psycopg2.errors.UniqueViolation as e:
            conn.rollback()
            msg = str(e)
            if "pppoe_login" in msg:
                flash(f"O login PPPoE '{pppoe_login}' já está cadastrado para outro cliente.", "danger")
            else:
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

    # Busca a senha atual do radcheck para exibir no formulário
    senha_radius_atual = "123"
    if cliente.get("pppoe_login"):
        with conn.cursor() as cur:
            cur.execute(
                "SELECT value FROM radcheck WHERE username = %s AND attribute = 'Cleartext-Password'",
                (cliente["pppoe_login"],),
            )
            row = cur.fetchone()
            if row:
                senha_radius_atual = row[0]

    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        ip = request.form.get("ip", "").strip()
        plano_id = request.form.get("plano_id", "").strip()
        pool_id = request.form.get("pool_id", "").strip()
        senha_radius = request.form.get("senha_radius", "").strip()

        if not plano_id:
            flash("Plano é obrigatório.", "danger")
            conn.close()
            return render_template("form_cliente.html", cliente=cliente, planos=planos, pools=pools,
                                   senha_radius_atual=senha_radius_atual)

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM planos WHERE id = %s", (plano_id,))
            plano_obj = cur.fetchone()

        if not plano_obj:
            flash("Plano selecionado não encontrado.", "danger")
            conn.close()
            return render_template("form_cliente.html", cliente=cliente, planos=planos, pools=pools,
                                   senha_radius_atual=senha_radius_atual)

        plano_nome = plano_obj["nome"]
        vel_down = plano_obj["velocidade_down"]
        vel_up = plano_obj["velocidade_up"]
        pool_id_val = int(pool_id) if pool_id else None

        if not check_ip_unique(conn, ip, cliente_id):
            flash(f"O IP {ip} já está em uso por outro cliente.", "danger")
            conn.close()
            return render_template("form_cliente.html", cliente=cliente, planos=planos, pools=pools,
                                   senha_radius_atual=senha_radius_atual)

        plano_changed = int(plano_id) != (cliente.get("plano_id") or 0)
        ip_changed = ip != (cliente.get("ip") or "")
        senha_changed = bool(senha_radius) and senha_radius != senha_radius_atual
        needs_disconnect = plano_changed or ip_changed or senha_changed

        with conn.cursor() as cur:
            cur.execute(
                """UPDATE clientes SET nome=%s, ip=%s, plano=%s, velocidade_down=%s,
                   velocidade_up=%s, plano_id=%s, pool_id=%s, atualizado_em=NOW() WHERE id=%s""",
                (nome, ip, plano_nome, vel_down, vel_up, int(plano_id), pool_id_val, cliente_id),
            )
        conn.commit()

        pppoe_login = cliente["pppoe_login"]
        if pppoe_login:
            # Determina qual senha usar: nova se fornecida, senão mantém a atual
            senha_para_salvar = senha_radius if senha_changed else senha_radius_atual
            upsert_radius_user(conn, pppoe_login, cliente["status"], vel_down, vel_up, ip,
                               senha=senha_para_salvar)
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
    return render_template("form_cliente.html", cliente=cliente, planos=planos, pools=pools,
                           senha_radius_atual=senha_radius_atual)


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
    ip_sgp = contrato.get("servico_ip") or ""
    ip_local = (cliente.get("ip") or "").strip()

    if pppoe_login and not check_pppoe_login_unique(conn, pppoe_login, cliente_id):
        conn.close()
        return jsonify({"error": f"Login PPPoE '{pppoe_login}' já pertence a outro cliente"}), 409

    # ip_local = IP real do cliente (setado manualmente ou vindo do SGP anteriormente)
    # O banco NUNCA recebe 10.24.x.x — esse IP vai apenas para o RADIUS
    # Prioridade: IP setado manualmente no painel > IP do SGP
    ip_banco = ip_local or ip_sgp

    if novo_status == "suspenso":
        ip_radius = alocar_ip_suspenso(conn)
    else:
        # Ativo: usa IP do banco (manual tem prioridade), fallback SGP
        ip_radius = ip_banco

    with conn.cursor() as cur:
        cur.execute(
            """UPDATE clientes SET status=%s, pppoe_login=%s, ip=COALESCE(NULLIF(%s, ''), ip),
               ultimo_sync_em=NOW(), atualizado_em=NOW() WHERE id=%s""",
            (novo_status, pppoe_login, ip_banco, cliente_id),
        )
    conn.commit()

    if pppoe_login:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT value FROM radcheck WHERE username = %s AND attribute = 'Cleartext-Password'",
                (pppoe_login,),
            )
            row = cur.fetchone()
        senha_atual = row[0] if row else "123"

        upsert_radius_user(
            conn, pppoe_login, novo_status,
            cliente["velocidade_down"], cliente["velocidade_up"], ip_radius,
            senha=senha_atual,
        )

    conn.close()
    return jsonify({"status": novo_status, "pppoe_login": pppoe_login, "ip": ip_banco})


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

        mikrotik_port = int(request.form.get("mikrotik_port", 8728) or 8728)

        if nasname and secret:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO nas (nasname, shortname, type, secret, description,
                       mikrotik_user, mikrotik_pass, mikrotik_port)
                       VALUES (%s, %s, 'other', %s, %s, %s, %s, %s)""",
                    (nasname, shortname, secret, description, mikrotik_user, mikrotik_pass, mikrotik_port),
                )
            conn.commit()
            flash("NAS adicionado com sucesso.", "success")

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM nas ORDER BY id")
        nas_list = cur.fetchall()

    conn.close()
    return render_template("nas.html", nas_list=nas_list, mikrotik_available=MIKROTIK_AVAILABLE)


@app.route("/nas/<int:nas_id>/editar", methods=["POST"])
@login_required
def editar_nas(nas_id):
    conn = get_db()
    nasname = request.form.get("nasname", "").strip()
    shortname = request.form.get("shortname", "").strip()
    secret = request.form.get("secret", "").strip()
    description = request.form.get("description", "").strip()
    mikrotik_user = request.form.get("mikrotik_user", "admin").strip()
    mikrotik_pass = request.form.get("mikrotik_pass", "").strip()
    mikrotik_port = int(request.form.get("mikrotik_port", 8728) or 8728)

    if nasname and secret:
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE nas SET nasname=%s, shortname=%s, secret=%s, description=%s,
                   mikrotik_user=%s, mikrotik_pass=%s, mikrotik_port=%s
                   WHERE id=%s""",
                (nasname, shortname, secret, description, mikrotik_user, mikrotik_pass, mikrotik_port, nas_id),
            )
        conn.commit()
        flash("NAS atualizado com sucesso.", "success")
    conn.close()
    return redirect(url_for("gerenciar_nas"))


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

    mt_port = int(nas.get("mikrotik_port") or 8728)

    try:
        api = librouteros.connect(
            host=nas["nasname"],
            username=mt_user,
            password=mt_pass,
            port=mt_port,
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


# ---------------------------------------------------------------------------
# Monitoramento MikroTik
# ---------------------------------------------------------------------------

@app.route("/monitoramento")
@login_required
def monitoramento():
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id, nasname, shortname FROM nas WHERE mikrotik_user IS NOT NULL AND mikrotik_pass IS NOT NULL AND mikrotik_pass != '' ORDER BY shortname")
        nas_list = cur.fetchall()
    conn.close()
    return render_template("monitoramento.html", nas_list=nas_list, mikrotik_available=MIKROTIK_AVAILABLE)


def _mt_connect(nas_id: int):
    """Retorna (api, nas_dict) ou lança exceção."""
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM nas WHERE id = %s", (nas_id,))
        nas = cur.fetchone()
    conn.close()
    if not nas:
        raise ValueError("NAS não encontrado")
    if not MIKROTIK_AVAILABLE:
        raise RuntimeError("librouteros não instalado")
    api = librouteros.connect(
        host=nas["nasname"],
        username=nas.get("mikrotik_user") or "admin",
        password=nas.get("mikrotik_pass") or "",
        port=int(nas.get("mikrotik_port") or 8728),
        timeout=8,
    )
    return api, nas


@app.route("/api/monitor/<int:nas_id>/interface")
@login_required
def monitor_interface(nas_id):
    """Retorna stats de todas as interfaces (ou filtra por nome via ?iface=sfp-sfpplus1)."""
    iface_filter = request.args.get("iface", "")
    try:
        api, _ = _mt_connect(nas_id)
        try:
            ifaces = list(api("/interface/print", **{"stats": ""}))
        finally:
            api.close()

        result = []
        for iface in ifaces:
            name = iface.get("name", "")
            if iface_filter and iface_filter.lower() not in name.lower():
                continue
            result.append({
                "name":       name,
                "type":       iface.get("type", ""),
                "running":    iface.get("running", "false"),
                "disabled":   iface.get("disabled", "false"),
                "rx_byte":    int(iface.get("rx-byte", 0)),
                "tx_byte":    int(iface.get("tx-byte", 0)),
                "rx_packet":  int(iface.get("rx-packet", 0)),
                "tx_packet":  int(iface.get("tx-packet", 0)),
                "rx_error":   int(iface.get("rx-error", 0)),
                "tx_error":   int(iface.get("tx-error", 0)),
                "rx_drop":    int(iface.get("rx-drop", 0)),
                "tx_drop":    int(iface.get("tx-drop", 0)),
                "link_downs": int(iface.get("link-downs", 0)),
            })
        return jsonify({"nas_id": nas_id, "interfaces": result, "ts": time.time()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/monitor/<int:nas_id>/recursos")
@login_required
def monitor_recursos(nas_id):
    """CPU, memória, uptime, versão do RouterOS."""
    try:
        api, _ = _mt_connect(nas_id)
        try:
            res = list(api("/system/resource/print"))
        finally:
            api.close()
        if not res:
            return jsonify({"error": "Sem dados de recursos"}), 500
        r = res[0]
        total_mem = int(r.get("total-memory", 0))
        free_mem  = int(r.get("free-memory", 0))
        used_mem  = total_mem - free_mem
        return jsonify({
            "cpu_load":      int(r.get("cpu-load", 0)),
            "uptime":        r.get("uptime", ""),
            "version":       r.get("version", ""),
            "board_name":    r.get("board-name", ""),
            "platform":      r.get("platform", ""),
            "total_mem_mb":  round(total_mem / 1048576, 1),
            "used_mem_mb":   round(used_mem  / 1048576, 1),
            "free_mem_mb":   round(free_mem  / 1048576, 1),
            "mem_pct":       round(used_mem / total_mem * 100, 1) if total_mem else 0,
            "total_hdd_mb":  round(int(r.get("total-hdd-space", 0)) / 1048576, 1),
            "free_hdd_mb":   round(int(r.get("free-hdd-space", 0))  / 1048576, 1),
            "ts": time.time(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/monitor/<int:nas_id>/overview")
@login_required
def monitor_overview(nas_id):
    """Resumo operacional do NAS para painel de monitoramento."""
    def as_bool(value):
        if isinstance(value, bool):
            return value
        return str(value).lower() in {"true", "yes", "on", "1"}

    def safe_int(value):
        try:
            return int(value)
        except Exception:
            return 0

    try:
        api, nas = _mt_connect(nas_id)
        try:
            identity_rows = list(api("/system/identity/print"))
            resource_rows = list(api("/system/resource/print"))
            clock_rows = list(api("/system/clock/print"))
            interfaces = list(api("/interface/print", **{"stats": ""}))
            dhcp_clients = list(api("/ip/dhcp-client/print"))
            routes = list(api("/ip/route/print"))
            ppp_active = list(api("/ppp/active/print"))

            # Temperatura
            try:
                health_rows = list(api("/system/health/print"))
            except Exception:
                health_rows = []

            # Wireless clients
            try:
                wireless_clients = list(api("/interface/wireless/registration-table/print"))
            except Exception:
                wireless_clients = []

            # VPN (L2TP / PPTP separados pelo campo "service")
            vpn_l2tp = [s for s in ppp_active if str(s.get("service", "")).lower() in ("l2tp", "l2tp-in")]
            vpn_pptp = [s for s in ppp_active if str(s.get("service", "")).lower() in ("pptp", "pptp-in")]

            # ARP
            try:
                arp_rows = list(api("/ip/arp/print"))
            except Exception:
                arp_rows = []

            # DNS cache count
            try:
                dns_cache = list(api("/ip/dns/cache/print"))
            except Exception:
                dns_cache = []

            # Firewall connections (count only — evita travar em roteadores com muitas conexões)
            try:
                fw_connections = list(api("/ip/firewall/connection/print", **{"count-only": ""}))
                # count-only retorna [{'ret': 'N'}] no RouterOS
                if fw_connections and isinstance(fw_connections[0], dict) and 'ret' in fw_connections[0]:
                    fw_connections = [None] * int(fw_connections[0]['ret'])
            except Exception:
                try:
                    fw_connections = list(api("/ip/firewall/connection/print"))
                except Exception:
                    fw_connections = []

            # Firewall drops (regras action=drop com packet count)
            try:
                fw_rules = list(api("/ip/firewall/filter/print", **{"stats": ""}))
                fw_drops = sum(
                    int(r.get("packets", 0))
                    for r in fw_rules
                    if str(r.get("action", "")).lower() == "drop"
                )
            except Exception:
                fw_drops = 0

            # Queues
            try:
                queues_simple = list(api("/queue/simple/print"))
            except Exception:
                queues_simple = []
            try:
                queues_tree = list(api("/queue/tree/print"))
            except Exception:
                queues_tree = []

            # Log (últimas 20 entradas)
            try:
                log_entries = list(api("/log/print"))[-20:]
            except Exception:
                log_entries = []

        finally:
            api.close()

        # Temperatura — campos variam por hardware
        cpu_temp = None
        board_temp = None
        for h in health_rows:
            name = str(h.get("name", "")).lower()
            val  = h.get("value", "")
            if "cpu" in name and "temp" in name:
                try: cpu_temp = float(val)
                except Exception: pass
            elif "board" in name and "temp" in name:
                try: board_temp = float(val)
                except Exception: pass
            elif "temperature" in name and cpu_temp is None:
                try: cpu_temp = float(val)
                except Exception: pass

        identity = identity_rows[0] if identity_rows else {}
        resource = resource_rows[0] if resource_rows else {}
        clock = clock_rows[0] if clock_rows else {}

        target_iface = None
        for iface in interfaces:
            name = str(iface.get("name", ""))
            if name == "sfp-sfpplus1":
                target_iface = iface
                break
        if target_iface is None:
            for iface in interfaces:
                name = str(iface.get("name", "")).lower()
                if "sfp" in name:
                    target_iface = iface
                    break

        iface_summary = None
        if target_iface:
            iface_summary = {
                "name": target_iface.get("name", "sfp-sfpplus1"),
                "type": target_iface.get("type", ""),
                "running": as_bool(target_iface.get("running", False)),
                "disabled": as_bool(target_iface.get("disabled", False)),
                "rx_byte": safe_int(target_iface.get("rx-byte", 0)),
                "tx_byte": safe_int(target_iface.get("tx-byte", 0)),
                "rx_packet": safe_int(target_iface.get("rx-packet", 0)),
                "tx_packet": safe_int(target_iface.get("tx-packet", 0)),
                "rx_error": safe_int(target_iface.get("rx-error", 0)),
                "tx_error": safe_int(target_iface.get("tx-error", 0)),
                "rx_drop": safe_int(target_iface.get("rx-drop", 0)),
                "tx_drop": safe_int(target_iface.get("tx-drop", 0)),
                "link_downs": safe_int(target_iface.get("link-downs", 0)),
            }

        dhcp_rows = []
        for row in dhcp_clients:
            dhcp_rows.append({
                "id": row.get(".id", ""),
                "interface": row.get("interface", ""),
                "status": row.get("status", "unknown"),
                "address": row.get("address", ""),
                "gateway": row.get("gateway", ""),
                "default_route_distance": row.get("default-route-distance", ""),
                "use_peer_dns": as_bool(row.get("use-peer-dns", False)),
                "running": as_bool(row.get("running", False)),
                "disabled": as_bool(row.get("disabled", False)),
                "slave": as_bool(row.get("slave", False)),
                "comment": row.get("comment", ""),
            })

        default_routes = []
        for route in routes:
            if str(route.get("dst-address", "")) != "0.0.0.0/0":
                continue
            default_routes.append({
                "gateway": route.get("gateway", ""),
                "distance": route.get("distance", ""),
                "active": as_bool(route.get("active", False)),
                "disabled": as_bool(route.get("disabled", False)),
                "routing_table": route.get("routing-table", "main"),
            })

        total_mem = safe_int(resource.get("total-memory", 0))
        free_mem = safe_int(resource.get("free-memory", 0))
        used_mem = max(0, total_mem - free_mem)

        return jsonify({
            "nas": {
                "id": nas_id,
                "nasname": nas.get("nasname", ""),
                "shortname": nas.get("shortname", ""),
                "identity": identity.get("name", ""),
            },
            "clock": {
                "date": clock.get("date", ""),
                "time": clock.get("time", ""),
                "timezone": clock.get("time-zone-name", ""),
            },
            "resource": {
                "cpu_load": safe_int(resource.get("cpu-load", 0)),
                "uptime": resource.get("uptime", ""),
                "version": resource.get("version", ""),
                "board_name": resource.get("board-name", ""),
                "platform": resource.get("platform", ""),
                "total_mem_mb": round(total_mem / 1048576, 1),
                "used_mem_mb": round(used_mem / 1048576, 1),
                "free_mem_mb": round(free_mem / 1048576, 1),
                "mem_pct": round((used_mem / total_mem) * 100, 1) if total_mem else 0,
                "free_hdd_mb": round(safe_int(resource.get("free-hdd-space", 0)) / 1048576, 1),
                "total_hdd_mb": round(safe_int(resource.get("total-hdd-space", 0)) / 1048576, 1),
            },
            "ppp_active_count": len(ppp_active),
            "sfp_interface": iface_summary,
            "dhcp_clients": dhcp_rows,
            "dhcp_slave_count": sum(1 for d in dhcp_rows if d["slave"]),
            "default_routes": default_routes,
            # Novos campos
            "temperature": {
                "cpu": cpu_temp,
                "board": board_temp,
            },
            "wireless_count": len(wireless_clients),
            "vpn": {
                "l2tp": len(vpn_l2tp),
                "pptp": len(vpn_pptp),
            },
            "arp_count": len([r for r in arp_rows if str(r.get("complete", "")).lower() in ("true", "yes", "1")]),
            "dns_cache_count": len(dns_cache),
            "firewall_connections": len(fw_connections),
            "firewall_drops": fw_drops,
            "queue_count": len(queues_simple) + len(queues_tree),
            "log_entries": [
                {
                    "time": e.get("time", ""),
                    "topics": e.get("topics", ""),
                    "message": e.get("message", ""),
                }
                for e in log_entries
            ],
            "ts": time.time(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/monitor/<int:nas_id>/ping")
@login_required
def monitor_ping(nas_id):
    """Ping a partir do MikroTik para um destino."""
    destino = request.args.get("destino", "8.8.8.8").strip()
    count   = min(int(request.args.get("count", 5)), 10)
    if not destino:
        return jsonify({"error": "Informe o destino"}), 400
    try:
        api, _ = _mt_connect(nas_id)
        try:
            result = list(api("/ping", **{
                "address": destino,
                "count":   str(count),
            }))
        finally:
            api.close()

        packets = []
        for p in result:
            packets.append({
                "seq":    p.get("seq", ""),
                "host":   p.get("host", destino),
                "time":   p.get("time", ""),
                "size":   p.get("size", ""),
                "ttl":    p.get("ttl", ""),
                "status": p.get("status", ""),
            })
        sent     = len(packets)
        received = sum(1 for p in packets if p.get("status", "") != "timeout")
        times    = [float(p["time"].replace("ms", "").strip()) for p in packets if p.get("time") and "ms" in p["time"]]
        return jsonify({
            "destino":  destino,
            "sent":     sent,
            "received": received,
            "loss_pct": round((sent - received) / sent * 100, 1) if sent else 0,
            "avg_ms":   round(sum(times) / len(times), 2) if times else None,
            "min_ms":   round(min(times), 2) if times else None,
            "max_ms":   round(max(times), 2) if times else None,
            "packets":  packets,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/monitor/<int:nas_id>/traceroute")
@login_required
def monitor_traceroute(nas_id):
    """Traceroute a partir do MikroTik."""
    destino = request.args.get("destino", "8.8.8.8").strip()
    if not destino:
        return jsonify({"error": "Informe o destino"}), 400
    try:
        api, _ = _mt_connect(nas_id)
        try:
            result = list(api("/ip/firewall/connection/print"))  # warmup
            hops = list(api("/tool/traceroute", **{
                "address":  destino,
                "count":    "3",
                "timeout":  "3000ms",
            }))
        finally:
            api.close()

        saltos = []
        for h in hops:
            saltos.append({
                "n":      h.get("n", ""),
                "host":   h.get("host", "*"),
                "loss":   h.get("loss", ""),
                "sent":   h.get("sent", ""),
                "last":   h.get("last", ""),
                "avg":    h.get("avg", ""),
                "best":   h.get("best", ""),
                "worst":  h.get("worst", ""),
                "status": h.get("status", ""),
            })
        return jsonify({"destino": destino, "hops": saltos})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/monitor/<int:nas_id>/speedtest")
@login_required
def monitor_speedtest(nas_id):
    """Speedtest via MikroTik (RouterOS 7.x — /tool/bandwidth-test para servidor interno
       ou speedtest nativo se disponível)."""
    try:
        api, nas = _mt_connect(nas_id)
        try:
            # Tenta speedtest nativo (RouterOS 7.4+)
            result = list(api("/tool/speedtest", **{}))
        except Exception:
            result = []
        finally:
            api.close()

        if result:
            r = result[0]
            return jsonify({
                "method":       "speedtest",
                "status":       r.get("status", ""),
                "download_mbps": round(int(r.get("download", 0)) / 1_000_000, 2),
                "upload_mbps":   round(int(r.get("upload", 0))   / 1_000_000, 2),
                "latency_ms":    r.get("latency", ""),
                "server":        r.get("server-name", ""),
                "isp":           r.get("isp", ""),
            })
        return jsonify({"error": "Speedtest não suportado neste RouterOS (requer v7.4+)"}), 422
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/monitor/<int:nas_id>/dns-lookup")
@login_required
def monitor_dns(nas_id):
    """DNS lookup a partir do MikroTik."""
    nome = request.args.get("nome", "google.com").strip()
    try:
        api, _ = _mt_connect(nas_id)
        try:
            result = list(api("/ip/dns/cache/print"))
        finally:
            api.close()
        # Filtra pelo nome consultado
        matches = [r for r in result if nome.lower() in (r.get("name") or "").lower()]
        return jsonify({"nome": nome, "registros": matches[:20]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/radius/reapply", methods=["POST"])
@login_required
def radius_reapply_all():
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM clientes WHERE pppoe_login IS NOT NULL AND pppoe_login != ''")
        clientes = cur.fetchall()

    # Busca senhas atuais de uma vez para não resetar senhas personalizadas
    with conn.cursor() as cur:
        cur.execute(
            "SELECT username, value FROM radcheck WHERE attribute = 'Cleartext-Password'"
        )
        senhas = {row[0]: row[1] for row in cur.fetchall()}

    count = 0
    for c in clientes:
        senha = senhas.get(c["pppoe_login"], "123")
        upsert_radius_user(conn, c["pppoe_login"], c["status"],
                           c["velocidade_down"], c["velocidade_up"], c["ip"] or "",
                           senha=senha)
        count += 1

    conn.close()
    flash(f"Atributos RADIUS reaplicados para {count} clientes.", "success")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Backup / Restauracao
# ---------------------------------------------------------------------------

BACKUP_SCHEMA = {
    "planos": ["id", "nome", "velocidade_down", "velocidade_up", "criado_em"],
    "pools": ["id", "nome", "range_inicio", "range_fim", "descricao", "criado_em"],
    "clientes": [
        "id", "nome", "cpf", "ip", "plano", "velocidade_down", "velocidade_up",
        "plano_id", "pool_id", "pppoe_login", "status", "ultimo_sync_em",
        "criado_em", "atualizado_em",
    ],
    "radcheck": ["id", "username", "attribute", "op", "value"],
    "radreply": ["id", "username", "attribute", "op", "value"],
    "radusergroup": ["id", "username", "groupname", "priority"],
    "alertas_consumo": [
        "id", "cliente_id", "limite_gb", "notificar_webhook", "notificar_email",
        "ativo", "ultimo_alerta_em", "criado_em",
    ],
}

BACKUP_TABLE_ORDER = [
    "planos",
    "pools",
    "clientes",
    "radcheck",
    "radreply",
    "radusergroup",
    "alertas_consumo",
]


@app.route("/clientes/importar", methods=["GET", "POST"])
@login_required
def importar_clientes():
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM planos ORDER BY nome")
        planos = cur.fetchall()
        cur.execute("SELECT * FROM pools ORDER BY nome")
        pools = cur.fetchall()

    if request.method == "GET":
        conn.close()
        return render_template("importar_clientes.html", planos=planos, pools=pools)

    # POST — processa o CSV
    arquivo = request.files.get("arquivo")
    plano_id = request.form.get("plano_id", "").strip()
    pool_id = request.form.get("pool_id", "").strip()

    if not arquivo or not arquivo.filename:
        flash("Selecione um arquivo CSV.", "danger")
        conn.close()
        return render_template("importar_clientes.html", planos=planos, pools=pools)

    if not plano_id:
        flash("Selecione um plano padrão para a importação.", "danger")
        conn.close()
        return render_template("importar_clientes.html", planos=planos, pools=pools)

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM planos WHERE id = %s", (plano_id,))
        plano_obj = cur.fetchone()

    if not plano_obj:
        flash("Plano não encontrado.", "danger")
        conn.close()
        return render_template("importar_clientes.html", planos=planos, pools=pools)

    pool_id_val = int(pool_id) if pool_id else None

    # Lê o CSV
    try:
        conteudo = arquivo.read().decode("utf-8-sig")  # utf-8-sig remove BOM se houver
    except UnicodeDecodeError:
        try:
            arquivo.seek(0)
            conteudo = arquivo.read().decode("latin-1")
        except Exception:
            flash("Não foi possível ler o arquivo. Use UTF-8 ou Latin-1.", "danger")
            conn.close()
            return render_template("importar_clientes.html", planos=planos, pools=pools)

    reader = csv.DictReader(io.StringIO(conteudo))

    # Detecta automaticamente as colunas nome e cpf (case-insensitive)
    if not reader.fieldnames:
        flash("CSV vazio ou sem cabeçalho.", "danger")
        conn.close()
        return render_template("importar_clientes.html", planos=planos, pools=pools)

    col_map = {c.strip().lower(): c for c in reader.fieldnames}
    col_nome = col_map.get("nome") or col_map.get("name") or col_map.get("cliente")
    col_cpf  = col_map.get("cpf") or col_map.get("documento") or col_map.get("cpf/cnpj")

    if not col_nome or not col_cpf:
        flash(
            f"Colunas obrigatórias não encontradas. O CSV deve ter colunas 'nome' e 'cpf'. "
            f"Colunas encontradas: {', '.join(reader.fieldnames)}",
            "danger"
        )
        conn.close()
        return render_template("importar_clientes.html", planos=planos, pools=pools)

    resultados = []  # lista de dicts com o resultado de cada linha
    importados = 0
    ignorados = 0
    erros = 0

    for i, row in enumerate(reader, start=2):  # começa em 2 pois linha 1 é cabeçalho
        nome = (row.get(col_nome) or "").strip()
        cpf  = re.sub(r"\D", "", row.get(col_cpf) or "")

        if not nome or not cpf:
            resultados.append({"linha": i, "nome": nome or "—", "cpf": cpf or "—",
                                "status": "erro", "detalhe": "Nome ou CPF vazio"})
            erros += 1
            continue

        if len(cpf) != 11:
            resultados.append({"linha": i, "nome": nome, "cpf": cpf,
                                "status": "erro", "detalhe": f"CPF inválido ({len(cpf)} dígitos)"})
            erros += 1
            continue

        # Verifica se CPF já existe
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM clientes WHERE cpf = %s", (cpf,))
            if cur.fetchone():
                resultados.append({"linha": i, "nome": nome, "cpf": cpf,
                                    "status": "ignorado", "detalhe": "CPF já cadastrado"})
                ignorados += 1
                continue

        # Consulta SGP
        contrato = consultar_sgp(cpf)
        pppoe_login = None
        status = "pendente"
        ip = ""

        if contrato:
            pppoe_login = contrato.get("contratoCentralLogin")
            status = status_from_sgp(contrato)
            ip = contrato.get("servico_ip") or ""

        # Auto-alocar IP do pool se necessário
        if not ip and pool_id_val:
            ip = alocar_ip_do_pool(conn, pool_id_val) or ""

        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO clientes (nome, cpf, ip, plano, velocidade_down, velocidade_up,
                       plano_id, pool_id, pppoe_login, status, ultimo_sync_em)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())""",
                    (nome, cpf, ip, plano_obj["nome"],
                     plano_obj["velocidade_down"], plano_obj["velocidade_up"],
                     int(plano_id), pool_id_val, pppoe_login, status),
                )
            conn.commit()

            if pppoe_login:
                upsert_radius_user(conn, pppoe_login, status,
                                   plano_obj["velocidade_down"], plano_obj["velocidade_up"], ip)

            detalhe = f"SGP: {status}" if contrato else "Sem resposta do SGP — pendente"
            resultados.append({"linha": i, "nome": nome, "cpf": cpf,
                                "status": "ok", "detalhe": detalhe,
                                "pppoe": pppoe_login or "—"})
            importados += 1

        except psycopg2.errors.UniqueViolation:
            conn.rollback()
            resultados.append({"linha": i, "nome": nome, "cpf": cpf,
                                "status": "ignorado", "detalhe": "Login PPPoE duplicado"})
            ignorados += 1
        except Exception as e:
            conn.rollback()
            resultados.append({"linha": i, "nome": nome, "cpf": cpf,
                                "status": "erro", "detalhe": str(e)})
            erros += 1

    conn.close()
    return render_template(
        "importar_clientes.html",
        planos=planos, pools=pools,
        resultados=resultados,
        resumo={"importados": importados, "ignorados": ignorados, "erros": erros},
    )


@app.route("/backup")
@login_required
def backup_restore():
    return render_template("backup_restore.html")


@app.route("/backup/export")
@login_required
def exportar_backup():
    payload = {
        "meta": {
            "version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": "radius-manager",
        },
        "tables": {},
    }

    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            for table in BACKUP_TABLE_ORDER:
                cols = BACKUP_SCHEMA[table]
                col_list = ", ".join(cols)
                cur.execute(f"SELECT {col_list} FROM {table}")
                payload["tables"][table] = cur.fetchall()
    finally:
        conn.close()

    content = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
    filename = f"backup_clientes_{time.strftime('%Y%m%d_%H%M%S')}.json"
    return Response(
        content,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/backup/restore", methods=["POST"])
@login_required
def restaurar_backup():
    file = request.files.get("backup_file")
    if not file or not file.filename:
        flash("Selecione um arquivo de backup JSON.", "danger")
        return redirect(url_for("backup_restore"))

    try:
        raw = file.read()
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        flash("Arquivo inválido. Envie um JSON de backup válido.", "danger")
        return redirect(url_for("backup_restore"))

    tables = data.get("tables") if isinstance(data, dict) else None
    if not isinstance(tables, dict):
        flash("Estrutura inválida: campo 'tables' não encontrado.", "danger")
        return redirect(url_for("backup_restore"))

    for required in ("planos", "pools", "clientes"):
        if required not in tables:
            flash(f"Backup inválido: tabela obrigatória ausente ({required}).", "danger")
            return redirect(url_for("backup_restore"))

    conn = get_db()
    try:
        with conn.cursor() as cur:
            # Limpa dados dependentes antes de restaurar
            cur.execute("DELETE FROM alertas_consumo")
            cur.execute("DELETE FROM radusergroup")
            cur.execute("DELETE FROM radreply")
            cur.execute("DELETE FROM radcheck")
            cur.execute("DELETE FROM clientes")
            cur.execute("DELETE FROM pools")
            cur.execute("DELETE FROM planos")

            # Restaura na ordem correta para manter FKs
            for table in BACKUP_TABLE_ORDER:
                rows = tables.get(table, [])
                if not isinstance(rows, list):
                    raise ValueError(f"Tabela {table} inválida no backup")

                allowed_cols = BACKUP_SCHEMA[table]
                col_list = ", ".join(allowed_cols)
                placeholders = ", ".join(["%s"] * len(allowed_cols))
                insert_sql = f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})"

                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    values = [row.get(col) for col in allowed_cols]
                    cur.execute(insert_sql, values)

            # Reajusta sequences para IDs explícitos restaurados
            seq_targets = [
                ("planos", "id"),
                ("pools", "id"),
                ("clientes", "id"),
                ("radcheck", "id"),
                ("radreply", "id"),
                ("radusergroup", "id"),
                ("alertas_consumo", "id"),
            ]
            for table, col in seq_targets:
                cur.execute(
                    f"SELECT setval(pg_get_serial_sequence('{table}', '{col}'), "
                    f"COALESCE((SELECT MAX({col}) FROM {table}), 1), "
                    f"(SELECT COUNT(*) > 0 FROM {table}))"
                )

        conn.commit()
        flash("Backup restaurado com sucesso.", "success")
    except Exception as e:
        conn.rollback()
        log.warning("Falha ao restaurar backup: %s", e)
        flash(f"Falha ao restaurar backup: {e}", "danger")
    finally:
        conn.close()

    return redirect(url_for("backup_restore"))


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
            # Validação de URL para webhooks (previne SSRF)
            if tipo == "webhook":
                from urllib.parse import urlparse
                parsed = urlparse(destino)
                blocked_hosts = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
                if parsed.scheme not in ("http", "https"):
                    flash("URL do webhook deve usar http:// ou https://", "danger")
                    conn.close()
                    return redirect(url_for("gerenciar_notificacoes"))
                if parsed.hostname in blocked_hosts:
                    flash("URL do webhook não pode apontar para localhost.", "danger")
                    conn.close()
                    return redirect(url_for("gerenciar_notificacoes"))
            elif tipo == "email" and "@" not in destino:
                flash("E-mail inválido.", "danger")
                conn.close()
                return redirect(url_for("gerenciar_notificacoes"))

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


@app.route("/api/v1/stats/historico")
@login_required
def api_stats_historico():
    """Dados de sessões agrupadas por hora para Chart.js."""
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT date_trunc('hour', acctstarttime) AS hora,
                   COUNT(DISTINCT username) AS sessoes
            FROM radacct
            WHERE acctstarttime >= NOW() - INTERVAL '24 hours'
            GROUP BY hora
            ORDER BY hora
        """)
        rows = cur.fetchall()
    conn.close()
    return jsonify([{"hora": str(r["hora"]), "sessoes": int(r["sessoes"])} for r in rows])


@app.route("/api/v1/online")
@api_key_required
def api_online():
    pagina = int(request.args.get("pagina", 1))
    por_pagina = min(int(request.args.get("por_pagina", 100)), 500)
    offset = (pagina - 1) * por_pagina

    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT COUNT(*) AS n FROM radacct WHERE acctstoptime IS NULL")
        total = cur.fetchone()["n"]
        cur.execute("""
            SELECT ra.username, ra.nasipaddress, ra.acctstarttime,
                   ra.acctinputoctets, ra.acctoutputoctets, ra.framedipaddress,
                   c.nome, c.plano
            FROM radacct ra
            LEFT JOIN clientes c ON c.pppoe_login = ra.username
            WHERE ra.acctstoptime IS NULL
            ORDER BY ra.acctstarttime DESC
            LIMIT %s OFFSET %s
        """, (por_pagina, offset))
        sessoes = cur.fetchall()
    conn.close()
    result = []
    for s in sessoes:
        d = dict(s)
        d["acctstarttime"] = str(d["acctstarttime"]) if d.get("acctstarttime") else None
        d["nasipaddress"] = str(d["nasipaddress"]) if d.get("nasipaddress") else None
        d["framedipaddress"] = str(d["framedipaddress"]) if d.get("framedipaddress") else None
        result.append(d)
    return jsonify({"total": total, "pagina": pagina, "por_pagina": por_pagina, "sessoes": result})


@app.route("/api/v1/noc/realtime")
@login_required
def api_noc_realtime():
    """KPIs operacionais em tempo real para o dashboard NOC."""
    churn_warn_pct = float(os.environ.get("NOC_CHURN_WARN_PCT", "5"))
    churn_crit_pct = float(os.environ.get("NOC_CHURN_CRIT_PCT", "12"))
    aaa_warn_pct = float(os.environ.get("NOC_AAA_WARN_PCT", "2"))
    aaa_crit_pct = float(os.environ.get("NOC_AAA_CRIT_PCT", "8"))

    def semaforo_from_pct(value: float, warn: float, crit: float, no_data: bool = False) -> str:
        if no_data:
            return "gray"
        if value >= crit:
            return "red"
        if value >= warn:
            return "yellow"
        return "green"

    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        # Sessões ativas por NAS
        cur.execute("""
            SELECT
                ra.nasipaddress::text AS nas_ip,
                COALESCE(NULLIF(n.shortname, ''), NULLIF(n.nasname, ''), ra.nasipaddress::text) AS nas_nome,
                COUNT(*) AS sessoes_ativas
            FROM radacct ra
            LEFT JOIN nas n ON host(ra.nasipaddress) = n.nasname
            WHERE ra.acctstoptime IS NULL
            GROUP BY ra.nasipaddress, nas_nome
            ORDER BY sessoes_ativas DESC, nas_nome
        """)
        nas_sessions = cur.fetchall()

        cur.execute("SELECT COUNT(*) AS total FROM radacct WHERE acctstoptime IS NULL")
        ativos_total = int(cur.fetchone()["total"])

        # Churn de conexão (última 1h): usuários com reconexão
        cur.execute("""
            WITH starts AS (
                SELECT username, COUNT(*) AS starts
                FROM radacct
                WHERE acctstarttime >= NOW() - INTERVAL '1 hour'
                GROUP BY username
            )
            SELECT
                COALESCE(SUM(starts), 0) AS starts_total,
                COUNT(*) AS usuarios_com_start,
                COALESCE(SUM(CASE WHEN starts > 1 THEN 1 ELSE 0 END), 0) AS usuarios_reconectaram
            FROM starts
        """)
        churn_row = cur.fetchone()

        cur.execute(
            "SELECT COUNT(*) AS stops_total FROM radacct WHERE acctstoptime >= NOW() - INTERVAL '1 hour'"
        )
        stops_total = int(cur.fetchone()["stops_total"])

        usuarios_com_start = int(churn_row["usuarios_com_start"])
        usuarios_reconectaram = int(churn_row["usuarios_reconectaram"])
        churn_pct_1h = round((usuarios_reconectaram / usuarios_com_start) * 100, 2) if usuarios_com_start else 0.0

        # Falhas AAA (última 1h)
        cur.execute("""
            SELECT
                COUNT(*) AS total_auth,
                COALESCE(SUM(CASE WHEN reply <> 'Access-Accept' THEN 1 ELSE 0 END), 0) AS falhas_auth
            FROM radpostauth
            WHERE authdate >= NOW() - INTERVAL '1 hour'
        """)
        aaa_row = cur.fetchone()

        cur.execute("""
            SELECT username, COUNT(*) AS falhas
            FROM radpostauth
            WHERE authdate >= NOW() - INTERVAL '1 hour'
              AND reply <> 'Access-Accept'
            GROUP BY username
            ORDER BY falhas DESC, username
            LIMIT 5
        """)
        top_falhas_aaa = cur.fetchall()

        # Mini série temporal de falhas AAA (últimos 60 minutos)
        cur.execute("""
            WITH buckets AS (
                SELECT generate_series(
                    date_trunc('minute', NOW()) - INTERVAL '59 minute',
                    date_trunc('minute', NOW()),
                    INTERVAL '1 minute'
                ) AS minuto
            ),
            agg AS (
                SELECT
                    date_trunc('minute', authdate) AS minuto,
                    COUNT(*) AS total_auth,
                    COALESCE(SUM(CASE WHEN reply <> 'Access-Accept' THEN 1 ELSE 0 END), 0) AS falhas_auth
                FROM radpostauth
                WHERE authdate >= NOW() - INTERVAL '60 minute'
                GROUP BY 1
            )
            SELECT
                b.minuto,
                COALESCE(a.total_auth, 0) AS total_auth,
                COALESCE(a.falhas_auth, 0) AS falhas_auth
            FROM buckets b
            LEFT JOIN agg a ON a.minuto = b.minuto
            ORDER BY b.minuto
        """)
        aaa_60m_rows = cur.fetchall()
    conn.close()

    total_auth = int(aaa_row["total_auth"])
    falhas_auth = int(aaa_row["falhas_auth"])
    taxa_falha_aaa_1h = round((falhas_auth / total_auth) * 100, 2) if total_auth else 0.0
    churn_semaforo = semaforo_from_pct(churn_pct_1h, churn_warn_pct, churn_crit_pct, no_data=(usuarios_com_start == 0))
    aaa_semaforo = semaforo_from_pct(taxa_falha_aaa_1h, aaa_warn_pct, aaa_crit_pct, no_data=(total_auth == 0))

    overall_semaforo = "green"
    if "red" in (churn_semaforo, aaa_semaforo):
        overall_semaforo = "red"
    elif "yellow" in (churn_semaforo, aaa_semaforo):
        overall_semaforo = "yellow"
    elif "gray" in (churn_semaforo, aaa_semaforo):
        overall_semaforo = "gray"

    return jsonify({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "semaforo": {
            "overall": overall_semaforo,
            "thresholds": {
                "churn_warn_pct": churn_warn_pct,
                "churn_crit_pct": churn_crit_pct,
                "aaa_warn_pct": aaa_warn_pct,
                "aaa_crit_pct": aaa_crit_pct,
            },
        },
        "ativos_total": ativos_total,
        "nas_sessions": [
            {
                "nas_ip": row["nas_ip"],
                "nas_nome": row["nas_nome"],
                "sessoes_ativas": int(row["sessoes_ativas"]),
            }
            for row in nas_sessions
        ],
        "churn_1h": {
            "starts_total": int(churn_row["starts_total"]),
            "stops_total": stops_total,
            "usuarios_com_start": usuarios_com_start,
            "usuarios_reconectaram": usuarios_reconectaram,
            "churn_pct": churn_pct_1h,
            "semaforo": churn_semaforo,
        },
        "aaa_1h": {
            "total_auth": total_auth,
            "falhas_auth": falhas_auth,
            "taxa_falha_pct": taxa_falha_aaa_1h,
            "semaforo": aaa_semaforo,
            "top_falhas": [
                {"username": row["username"], "falhas": int(row["falhas"])}
                for row in top_falhas_aaa
            ],
        },
        "aaa_60m": [
            {
                "minuto": row["minuto"].isoformat() if row.get("minuto") else None,
                "total_auth": int(row["total_auth"]),
                "falhas_auth": int(row["falhas_auth"]),
                "taxa_falha_pct": round((int(row["falhas_auth"]) / int(row["total_auth"])) * 100, 2)
                if int(row["total_auth"]) > 0 else 0.0,
            }
            for row in aaa_60m_rows
        ],
    })


# ---------------------------------------------------------------------------
# Alertas de consumo
# ---------------------------------------------------------------------------

@app.route("/alertas-consumo", methods=["GET", "POST"])
@login_required
def alertas_consumo():
    conn = get_db()

    if request.method == "POST":
        cliente_id = request.form.get("cliente_id", "").strip()
        limite_gb = request.form.get("limite_gb", "").strip()
        notificar_webhook = bool(request.form.get("notificar_webhook"))
        notificar_email = bool(request.form.get("notificar_email"))

        if not cliente_id or not limite_gb:
            flash("Cliente e limite são obrigatórios.", "danger")
        else:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """INSERT INTO alertas_consumo
                           (cliente_id, limite_gb, notificar_webhook, notificar_email)
                           VALUES (%s, %s, %s, %s)""",
                        (int(cliente_id), float(limite_gb),
                         notificar_webhook, notificar_email),
                    )
                conn.commit()
                flash("Alerta configurado com sucesso.", "success")
            except Exception as e:
                conn.rollback()
                flash(f"Erro: {e}", "danger")

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT ac.*, c.nome AS cliente_nome, c.pppoe_login
            FROM alertas_consumo ac
            JOIN clientes c ON c.id = ac.cliente_id
            ORDER BY ac.criado_em DESC
        """)
        alertas = cur.fetchall()
        cur.execute("SELECT id, nome FROM clientes ORDER BY nome")
        clientes_lista = cur.fetchall()

    conn.close()
    return render_template("alertas_consumo.html", alertas=alertas, clientes=clientes_lista)


@app.route("/alertas-consumo/<int:alerta_id>/excluir", methods=["POST"])
@login_required
def excluir_alerta_consumo(alerta_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM alertas_consumo WHERE id = %s", (alerta_id,))
    conn.commit()
    conn.close()
    flash("Alerta removido.", "success")
    return redirect(url_for("alertas_consumo"))


@app.route("/alertas-consumo/<int:alerta_id>/toggle", methods=["POST"])
@login_required
def toggle_alerta_consumo(alerta_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("UPDATE alertas_consumo SET ativo = NOT ativo WHERE id = %s", (alerta_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("alertas_consumo"))


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    status = {"status": "ok", "services": {}}

    # PostgreSQL
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
        conn.close()
        status["services"]["postgres"] = "ok"
    except Exception as e:
        status["services"]["postgres"] = f"error: {e}"
        status["status"] = "degraded"

    # Redis
    r = get_redis()
    if r:
        status["services"]["redis"] = "ok"
    else:
        status["services"]["redis"] = "unavailable"
        status["status"] = "degraded"

    # Sync status (from Redis)
    if r:
        last_sync = r.get("sync:last_run")
        sync_error = r.get("sync:last_error")
        status["sync"] = {
            "last_run": last_sync,
            "last_error": sync_error,
        }

    http_status = 200 if status["status"] == "ok" else 207
    return jsonify(status), http_status


# ---------------------------------------------------------------------------
# SSE — stats em tempo real
# ---------------------------------------------------------------------------

@app.route("/stream/stats")
@login_required
def stream_stats():
    def generate():
        while True:
            try:
                online_users = get_online_users()
                conn = get_db()
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("SELECT COUNT(*) AS n FROM clientes")
                    total = cur.fetchone()["n"]
                    cur.execute("SELECT COUNT(*) AS n FROM clientes WHERE status='suspenso'")
                    suspensos = cur.fetchone()["n"]
                    # Conta apenas online que estão cadastrados localmente (evita negativo)
                    if online_users:
                        placeholders = ",".join(["%s"] * len(online_users))
                        cur.execute(
                            f"SELECT COUNT(*) AS n FROM clientes WHERE pppoe_login IN ({placeholders})",
                            list(online_users),
                        )
                        total_online_cadastrados = cur.fetchone()["n"]
                    else:
                        total_online_cadastrados = 0
                conn.close()

                total_online = total_online_cadastrados
                payload = json.dumps({
                    "total_clientes": total,
                    "total_online": total_online,
                    "total_offline": max(0, total - total_online),
                    "total_suspensos": suspensos,
                })

                r = get_redis()
                sync_info = {}
                if r:
                    sync_info = {
                        "last_run": r.get("sync:last_run"),
                        "last_error": r.get("sync:last_error"),
                    }
                payload = json.dumps({
                    "total_clientes": total,
                    "total_online": total_online,
                    "total_offline": total - total_online,
                    "total_suspensos": suspensos,
                    "sync": sync_info,
                })
                yield f"data: {payload}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'error': str(e)})}\n\n"
            # Usa gevent.sleep se disponível (não bloqueia o worker)
            try:
                from gevent import sleep as gsleep
                gsleep(15)
            except ImportError:
                time.sleep(15)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# CPE / TR-069 — GenieACS integration
# ---------------------------------------------------------------------------

def _cpe_ensure_table():
    """Garante que a tabela cpe_devices existe (auto-migrate)."""
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cpe_devices (
                id SERIAL PRIMARY KEY,
                cliente_id INTEGER REFERENCES clientes(id) ON DELETE SET NULL,
                serial_number VARCHAR(150),
                mac_address VARCHAR(20),
                modelo VARCHAR(150),
                fabricante VARCHAR(100),
                genieacs_id VARCHAR(300) UNIQUE,
                ip_wan VARCHAR(50),
                ip_lan VARCHAR(50),
                online BOOLEAN DEFAULT FALSE,
                ultima_conexao TIMESTAMP,
                rx_power FLOAT,
                ssid VARCHAR(100),
                ssid_5g VARCHAR(100),
                ssid_24g VARCHAR(100),
                firmware_version VARCHAR(100),
                uptime_seconds INTEGER DEFAULT 0,
                obs TEXT,
                criado_em TIMESTAMP DEFAULT NOW(),
                atualizado_em TIMESTAMP DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS cpe_devices_cliente_id  ON cpe_devices(cliente_id);
            CREATE INDEX IF NOT EXISTS cpe_devices_genieacs_id ON cpe_devices(genieacs_id);
            ALTER TABLE cpe_devices ADD COLUMN IF NOT EXISTS ssid_24g VARCHAR(100);
        """)
    conn.commit()
    conn.close()


@app.route("/cpe")
@login_required
def cpe_lista():
    _cpe_ensure_table()
    genieacs_ok = _genieacs.ping()
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT c.id AS cliente_id, c.nome AS cliente_nome, c.pppoe_login,
                   c.status AS cliente_status, c.plano,
                   cpe.id, cpe.serial_number, cpe.modelo, cpe.fabricante,
                   cpe.genieacs_id, cpe.ip_wan, cpe.online, cpe.ultima_conexao,
                   cpe.rx_power, cpe.ssid, cpe.firmware_version, cpe.obs
            FROM cpe_devices cpe
            JOIN clientes c ON c.id = cpe.cliente_id
            ORDER BY cpe.online DESC, c.nome
        """)
        cpes_vinculados = cur.fetchall()

        # Clientes sem CPE vinculado (para o modal de vincular)
        cur.execute("""
            SELECT c.id, c.nome, c.pppoe_login, c.plano
            FROM clientes c
            WHERE NOT EXISTS (SELECT 1 FROM cpe_devices cpe WHERE cpe.cliente_id = c.id)
            ORDER BY c.nome
        """)
        clientes_sem_cpe = cur.fetchall()

        # Estatísticas rápidas
        cur.execute("SELECT COUNT(*) AS n, COUNT(*) FILTER (WHERE online) AS on_ FROM cpe_devices")
        stats = cur.fetchone()
    conn.close()

    return render_template("cpe_lista.html",
        cpes=cpes_vinculados,
        clientes_sem_cpe=clientes_sem_cpe,
        stats=stats,
        genieacs_ok=genieacs_ok,
    )


@app.route("/cpe/<int:cpe_id>")
@login_required
def cpe_detalhe(cpe_id):
    _cpe_ensure_table()
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT cpe.*, c.nome AS cliente_nome, c.pppoe_login, c.plano,
                   c.velocidade_down, c.velocidade_up, c.status AS cliente_status,
                   c.ip AS cliente_ip, c.id AS cliente_id
            FROM cpe_devices cpe
            JOIN clientes c ON c.id = cpe.cliente_id
            WHERE cpe.id = %s
        """, (cpe_id,))
        cpe = cur.fetchone()
    conn.close()
    if not cpe:
        flash("CPE não encontrado.", "danger")
        return redirect(url_for("cpe_lista"))

    # Busca dados ao vivo do GenieACS
    live = None
    genieacs_ok = _genieacs.ping()
    if genieacs_ok and cpe["genieacs_id"]:
        try:
            raw = _genieacs.get_device(cpe["genieacs_id"])
            if raw:
                live = _genieacs.parse_device(raw)
        except Exception as e:
            log.warning("GenieACS get_device error: %s", e)

    return render_template("cpe_detalhe.html", cpe=cpe, live=live, genieacs_ok=genieacs_ok)


@app.route("/cpe/vincular", methods=["POST"])
@login_required
def cpe_vincular():
    """Vincula um device GenieACS a um cliente do sistema."""
    _cpe_ensure_table()
    genieacs_id = request.form.get("genieacs_id", "").strip()
    cliente_id  = request.form.get("cliente_id", "").strip()
    obs         = request.form.get("obs", "").strip()

    if not genieacs_id or not cliente_id:
        flash("Preencha todos os campos.", "danger")
        return redirect(url_for("cpe_lista"))

    try:
        raw = _genieacs.get_device(genieacs_id)
        if not raw:
            flash("Device não encontrado no GenieACS.", "danger")
            return redirect(url_for("cpe_lista"))
        parsed = _genieacs.parse_device(raw)
    except Exception as e:
        flash(f"Erro ao consultar GenieACS: {e}", "danger")
        return redirect(url_for("cpe_lista"))

    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO cpe_devices
                (cliente_id, serial_number, mac_address, modelo, fabricante, genieacs_id,
                 ip_wan, ip_lan, online, ultima_conexao, rx_power, ssid, ssid_5g, ssid_24g,
                 firmware_version, uptime_seconds, obs)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (genieacs_id) DO UPDATE SET
                cliente_id=EXCLUDED.cliente_id, ip_wan=EXCLUDED.ip_wan,
                online=EXCLUDED.online, ultima_conexao=EXCLUDED.ultima_conexao,
                rx_power=EXCLUDED.rx_power, ssid=EXCLUDED.ssid, ssid_5g=EXCLUDED.ssid_5g,
                ssid_24g=EXCLUDED.ssid_24g, firmware_version=EXCLUDED.firmware_version,
                uptime_seconds=EXCLUDED.uptime_seconds, obs=EXCLUDED.obs,
                atualizado_em=NOW()
        """, (
            cliente_id, parsed["serial"], parsed["mac_wan"],
            parsed["modelo"], parsed["fabricante"], genieacs_id,
            parsed["ip_wan"], parsed["ip_lan"],
            parsed["online"],
            datetime.now(timezone.utc) if parsed["online"] else None,
            parsed["rx_power"], parsed["ssid"], parsed["ssid_5g"], parsed["ssid_24g"],
            parsed["firmware"], parsed["uptime_sec"], obs,
        ))
    conn.commit()
    conn.close()
    flash("CPE vinculado com sucesso!", "success")
    return redirect(url_for("cpe_lista"))


@app.route("/cpe/<int:cpe_id>/desvincular", methods=["POST"])
@login_required
def cpe_desvincular(cpe_id):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM cpe_devices WHERE id=%s", (cpe_id,))
    conn.commit()
    conn.close()
    flash("CPE desvinculado.", "success")
    return redirect(url_for("cpe_lista"))


@app.route("/cpe/<int:cpe_id>/reboot", methods=["POST"])
@login_required
def cpe_reboot(cpe_id):
    cpe = _get_cpe_or_404(cpe_id)
    if not cpe:
        return jsonify({"error": "CPE não encontrado"}), 404
    try:
        _genieacs.reboot(cpe["genieacs_id"])
        return jsonify({"ok": True, "msg": "Reboot enviado ao CPE."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/cpe/<int:cpe_id>/factory-reset", methods=["POST"])
@login_required
def cpe_factory_reset(cpe_id):
    cpe = _get_cpe_or_404(cpe_id)
    if not cpe:
        return jsonify({"error": "CPE não encontrado"}), 404
    try:
        _genieacs.factory_reset(cpe["genieacs_id"])
        return jsonify({"ok": True, "msg": "Reset de fábrica enviado."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/cpe/<int:cpe_id>/refresh", methods=["POST"])
@login_required
def cpe_refresh(cpe_id):
    cpe = _get_cpe_or_404(cpe_id)
    if not cpe:
        return jsonify({"error": "CPE não encontrado"}), 404
    try:
        _genieacs.refresh(cpe["genieacs_id"])
        return jsonify({"ok": True, "msg": "Refresh enviado."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/cpe/<int:cpe_id>/wifi", methods=["POST"])
@login_required
def cpe_set_wifi(cpe_id):
    """Altera SSID e/ou senha Wi-Fi via TR-069."""
    cpe = _get_cpe_or_404(cpe_id)
    if not cpe:
        return jsonify({"error": "CPE não encontrado"}), 404

    ssid     = request.json.get("ssid", "").strip()
    password = request.json.get("password", "").strip()
    band     = request.json.get("band", "2.4")   # "2.4" ou "5"

    if not ssid and not password:
        return jsonify({"error": "Informe SSID ou senha."}), 400

    # Monta paths TR-098 para Intelbras AX1800:
    # WLANConfiguration.1 = 5 GHz, WLANConfiguration.6 = 2.4 GHz
    # Também tenta TR-181 Device.WiFi.* como fallback
    if band == "5":
        ssid_paths = ["InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID",
                      "Device.WiFi.SSID.1.SSID"]
        pass_paths = ["InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.KeyPassphrase",
                      "Device.WiFi.AccessPoint.1.Security.KeyPassphrase"]
    else:
        ssid_paths = ["InternetGatewayDevice.LANDevice.1.WLANConfiguration.6.SSID",
                      "Device.WiFi.SSID.6.SSID"]
        pass_paths = ["InternetGatewayDevice.LANDevice.1.WLANConfiguration.6.KeyPassphrase",
                      "Device.WiFi.AccessPoint.6.Security.KeyPassphrase"]

    params = []
    if ssid:
        params.append([ssid_paths[0], ssid, "xsd:string"])
    if password:
        params.append([pass_paths[0], password, "xsd:string"])

    try:
        _genieacs.set_params(cpe["genieacs_id"], params)
        # Atualiza SSID no banco local também
        if ssid:
            conn = get_db()
            col = "ssid_5g" if band == "5" else "ssid_24g"
            with conn.cursor() as cur:
                cur.execute(f"UPDATE cpe_devices SET {col}=%s, atualizado_em=NOW() WHERE id=%s", (ssid, cpe_id))
            conn.commit()
            conn.close()
        return jsonify({"ok": True, "msg": "Configuração Wi-Fi enviada ao CPE."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/cpe/<int:cpe_id>/status")
@login_required
def cpe_api_status(cpe_id):
    """Retorna status ao vivo do CPE para polling do frontend."""
    cpe = _get_cpe_or_404(cpe_id)
    if not cpe:
        return jsonify({"error": "CPE não encontrado"}), 404
    if not _genieacs.ping():
        return jsonify({"error": "GenieACS indisponível"}), 503
    try:
        raw = _genieacs.get_device(cpe["genieacs_id"])
        if not raw:
            return jsonify({"online": False})
        parsed = _genieacs.parse_device(raw)
        return jsonify(parsed)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/cpe/sync", methods=["POST"])
@login_required
def cpe_sync_all():
    """Sincroniza status de todos os CPEs vinculados com o GenieACS."""
    _cpe_ensure_table()
    if not _genieacs.ping():
        return jsonify({"error": "GenieACS indisponível"}), 503

    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id, genieacs_id FROM cpe_devices WHERE genieacs_id IS NOT NULL")
        cpes = cur.fetchall()
    conn.close()

    updated = 0
    errors = 0
    for cpe in cpes:
        try:
            raw = _genieacs.get_device(cpe["genieacs_id"])
            if not raw:
                continue
            p = _genieacs.parse_device(raw)
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE cpe_devices SET
                        ip_wan=%s, ip_lan=%s, online=%s,
                        ultima_conexao=CASE WHEN %s THEN NOW() ELSE ultima_conexao END,
                        rx_power=%s, ssid=%s, ssid_5g=%s, ssid_24g=%s,
                        firmware_version=%s, uptime_seconds=%s, atualizado_em=NOW()
                    WHERE id=%s
                """, (
                    p["ip_wan"], p["ip_lan"], p["online"], p["online"],
                    p["rx_power"], p["ssid"], p["ssid_5g"], p["ssid_24g"],
                    p["firmware"], p["uptime_sec"], cpe["id"],
                ))
            conn.commit()
            conn.close()
            updated += 1
        except Exception as e:
            log.warning("CPE sync error id=%s: %s", cpe["id"], e)
            errors += 1

    return jsonify({"updated": updated, "errors": errors, "total": len(cpes)})


@app.route("/api/cpe/genieacs/devices")
@login_required
def cpe_genieacs_devices():
    """Lista devices do GenieACS que ainda não estão vinculados no sistema."""
    if not _genieacs.ping():
        return jsonify({"error": "GenieACS indisponível"}), 503
    try:
        raw_list = _genieacs.list_devices(limit=500)
        # IDs já vinculados
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT genieacs_id FROM cpe_devices WHERE genieacs_id IS NOT NULL")
            vinculados = {r[0] for r in cur.fetchall()}
        conn.close()

        result = []
        for raw in raw_list:
            p = _genieacs.parse_device(raw)
            p["ja_vinculado"] = p["genieacs_id"] in vinculados
            result.append(p)

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _get_cpe_or_404(cpe_id):
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM cpe_devices WHERE id=%s", (cpe_id,))
        cpe = cur.fetchone()
    conn.close()
    return cpe


# ---------------------------------------------------------------------------
# Relatórios
# ---------------------------------------------------------------------------

@app.route("/relatorios")
@login_required
def relatorios():
    conn = get_db()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:

        # Top 10 consumidores — janela adaptativa: tenta 30 dias, cai para todo histórico
        cur.execute("""
            SELECT ra.username,
                   c.nome,
                   c.plano,
                   SUM(ra.acctinputoctets + ra.acctoutputoctets) AS total_bytes,
                   SUM(ra.acctinputoctets)  AS download_bytes,
                   SUM(ra.acctoutputoctets) AS upload_bytes,
                   COUNT(*) AS num_sessoes
            FROM radacct ra
            LEFT JOIN clientes c ON c.pppoe_login = ra.username
            GROUP BY ra.username, c.nome, c.plano
            ORDER BY total_bytes DESC
            LIMIT 10
        """)
        top_consumidores = cur.fetchall()

        # Sessões históricas recentes (últimas 100 — ativas primeiro, depois encerradas)
        cur.execute("""
            SELECT ra.username, c.nome,
                   ra.acctstarttime, ra.acctstoptime,
                   ra.acctsessiontime,
                   ra.acctinputoctets  AS download_bytes,
                   ra.acctoutputoctets AS upload_bytes,
                   ra.framedipaddress,
                   ra.nasipaddress
            FROM radacct ra
            LEFT JOIN clientes c ON c.pppoe_login = ra.username
            ORDER BY (ra.acctstoptime IS NULL) DESC, ra.acctstarttime DESC
            LIMIT 100
        """)
        sessoes_historicas = cur.fetchall()

        # Sessões ativas agora
        cur.execute("SELECT COUNT(*) AS n FROM radacct WHERE acctstoptime IS NULL")
        sessoes_ativas = int(cur.fetchone()["n"])

        # Resumo geral do mês atual
        cur.execute("""
            SELECT
                COUNT(DISTINCT username)                            AS clientes_ativos,
                COUNT(*)                                            AS total_sessoes,
                COALESCE(SUM(acctinputoctets + acctoutputoctets),0) AS total_bytes,
                COALESCE(AVG(CASE WHEN acctstoptime IS NOT NULL THEN acctsessiontime END), 0) AS avg_session_secs
            FROM radacct
            WHERE acctstarttime >= date_trunc('month', NOW())
        """)
        resumo_mes = cur.fetchone()

        # Se o mês está zerado, tenta todo o histórico como fallback
        resumo_periodo = "mês atual"
        if not resumo_mes["clientes_ativos"] and not resumo_mes["total_sessoes"]:
            cur.execute("""
                SELECT
                    COUNT(DISTINCT username)                            AS clientes_ativos,
                    COUNT(*)                                            AS total_sessoes,
                    COALESCE(SUM(acctinputoctets + acctoutputoctets),0) AS total_bytes,
                    COALESCE(AVG(CASE WHEN acctstoptime IS NOT NULL THEN acctsessiontime END), 0) AS avg_session_secs
                FROM radacct
            """)
            resumo_mes = cur.fetchone()
            resumo_periodo = "todo o histórico"

        # Dados para gráfico: sessões ativas por hora nas últimas 24h
        cur.execute("""
            SELECT date_trunc('hour', acctstarttime) AS hora,
                   COUNT(DISTINCT username) AS qtd
            FROM radacct
            WHERE acctstarttime >= NOW() - INTERVAL '24 hours'
            GROUP BY hora
            ORDER BY hora
        """)
        grafico_24h = cur.fetchall()

        # Se não há dados nas últimas 24h, pega todo histórico agrupado por dia
        if not grafico_24h:
            cur.execute("""
                SELECT date_trunc('day', acctstarttime) AS hora,
                       COUNT(DISTINCT username) AS qtd
                FROM radacct
                GROUP BY hora
                ORDER BY hora
                LIMIT 30
            """)
            grafico_24h = cur.fetchall()

    conn.close()

    # Formata bytes para exibição
    def fmt_bytes(b):
        b = b or 0
        if b >= 1_073_741_824:
            return f"{b/1_073_741_824:.2f} GB"
        if b >= 1_048_576:
            return f"{b/1_048_576:.2f} MB"
        if b >= 1024:
            return f"{b/1024:.2f} KB"
        return f"{b} B"

    for row in top_consumidores:
        row["total_fmt"]    = fmt_bytes(row["total_bytes"])
        row["download_fmt"] = fmt_bytes(row["download_bytes"])
        row["upload_fmt"]   = fmt_bytes(row["upload_bytes"])

    for row in sessoes_historicas:
        row["download_fmt"] = fmt_bytes(row["download_bytes"])
        row["upload_fmt"]   = fmt_bytes(row["upload_bytes"])
        secs = row.get("acctsessiontime") or 0
        # Para sessões ativas, calcula tempo desde acctstarttime
        if not row.get("acctstoptime") and row.get("acctstarttime"):
            from datetime import timezone as tz
            start = row["acctstarttime"]
            if start.tzinfo is None:
                start = start.replace(tzinfo=tz.utc)
            secs = int((datetime.now(tz.utc) - start).total_seconds())
        h, m = divmod(int(secs) // 60, 60)
        row["duracao_fmt"] = f"{h}h {m}m" if h else f"{m}m"
        row["ativa"] = not row.get("acctstoptime")

    resumo_mes["total_fmt"] = fmt_bytes(resumo_mes["total_bytes"])
    avg_secs = int(resumo_mes.get("avg_session_secs") or 0)
    h, m = divmod(avg_secs // 60, 60)
    resumo_mes["avg_fmt"] = f"{h}h {m}m" if h else f"{m}m"
    resumo_mes["sessoes_ativas"] = sessoes_ativas

    grafico_labels = [str(r["hora"]) for r in grafico_24h]
    grafico_values = [int(r["qtd"]) for r in grafico_24h]

    return render_template(
        "relatorios.html",
        top_consumidores=top_consumidores,
        sessoes_historicas=sessoes_historicas,
        resumo_mes=resumo_mes,
        resumo_periodo=resumo_periodo,
        grafico_labels=json.dumps(grafico_labels),
        grafico_values=json.dumps(grafico_values),
    )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

with app.app_context():
    create_default_admin()

if __name__ == "__main__":
    app.run(debug=False)
