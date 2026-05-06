"""
Serviço de sincronização automática com o SGP.
Roda em loop consultando todos os clientes cadastrados e atualiza
o status no banco + tabelas do FreeRADIUS.
Envia notificações (email/webhook) quando o status muda.
"""
import os
import time
import json
import smtplib
import logging
import ipaddress
import requests
import psycopg2
import psycopg2.extras
from datetime import datetime, timezone
from email.mime.text import MIMEText

SUSPENSION_NETWORK = ipaddress.ip_network("10.24.0.0/20", strict=False)


class JsonFormatter(logging.Formatter):
    def format(self, record):
        obj = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": "sync",
            "msg": record.getMessage(),
        }
        if record.exc_info:
            obj["exc"] = self.formatException(record.exc_info)
        return json.dumps(obj, ensure_ascii=False)

_handler = logging.StreamHandler()
_handler.setFormatter(JsonFormatter())
logging.basicConfig(level=logging.INFO, handlers=[_handler])
log = logging.getLogger(__name__)

SGP_URL = os.environ.get("SGP_URL", "https://linknetam.sgp.net.br/api/ura/consultacliente/")
SGP_TOKEN = os.environ.get("SGP_TOKEN", "")
SGP_APP = os.environ.get("SGP_APP", "APP")
SYNC_INTERVAL = int(os.environ.get("SYNC_INTERVAL", "300"))

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")


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


def consultar_sgp(cpf: str) -> dict | None:
    try:
        resp = requests.post(
            SGP_URL,
            data={"token": SGP_TOKEN, "app": SGP_APP, "cpfcnpj": cpf},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        contratos = data.get("contratos", [])
        if contratos:
            return contratos[0]
        log.warning("SGP sem contratos para cpf=%s. Resposta: %s", cpf, data)
    except requests.RequestException as e:
        log.warning("Falha HTTP ao consultar SGP para cpf=%s: %s", cpf, e)
    except Exception as e:
        log.warning("Erro inesperado ao consultar SGP para cpf=%s: %s", cpf, e)
    return None


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


def upsert_radius_user(conn, login: str, status: str, down: int, up: int, ip: str = "", senha: str = ""):
    # Preserva senha personalizada — busca do banco se não foi fornecida
    if not senha:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT value FROM radcheck WHERE username = %s AND attribute = 'Cleartext-Password'",
                (login,),
            )
            row = cur.fetchone()
        senha = row[0] if row else "123"

    with conn.cursor() as cur:
        cur.execute("DELETE FROM radcheck WHERE username = %s", (login,))
        cur.execute("DELETE FROM radreply WHERE username = %s", (login,))

        if status == "ativo":
            cur.execute(
                "INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, %s, %s, %s)",
                (login, "Cleartext-Password", ":=", senha),
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
            cur.execute(
                "INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, %s, %s, %s)",
                (login, "Cleartext-Password", ":=", senha),
            )
            if ip:
                cur.execute(
                    "INSERT INTO radreply (username, attribute, op, value) VALUES (%s, %s, %s, %s)",
                    (login, "Framed-IP-Address", ":=", ip),
                )
        else:
            # pendente ou outro status — nega acesso
            cur.execute(
                "INSERT INTO radcheck (username, attribute, op, value) VALUES (%s, %s, %s, %s)",
                (login, "Auth-Type", ":=", "Reject"),
            )
    conn.commit()


def send_notifications(conn, cliente: dict, old_status: str, new_status: str):
    """Envia notificações (email/webhook) quando o status de um cliente muda."""
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM notificacoes_config WHERE ativo = TRUE")
            configs = cur.fetchall()
    except Exception as e:
        log.warning("Erro ao buscar configs de notificação: %s", e)
        return

    if not configs:
        return

    nome = cliente.get("nome", "desconhecido")
    cpf = cliente.get("cpf", "")
    login = cliente.get("pppoe_login", "")
    msg_text = (
        f"Cliente: {nome}\n"
        f"CPF: {cpf}\n"
        f"Login PPPoE: {login}\n"
        f"Status alterado: {old_status} → {new_status}"
    )

    for config in configs:
        if config["tipo"] == "webhook":
            try:
                requests.post(
                    config["destino"],
                    json={
                        "event": "status_change",
                        "cliente_nome": nome,
                        "cpf": cpf,
                        "pppoe_login": login,
                        "old_status": old_status,
                        "new_status": new_status,
                    },
                    timeout=5,
                )
                log.info("Webhook enviado para %s (cliente=%s)", config["destino"], nome)
            except Exception as e:
                log.warning("Falha ao enviar webhook para %s: %s", config["destino"], e)

        elif config["tipo"] == "email":
            if not SMTP_HOST or not SMTP_USER:
                log.warning("SMTP não configurado — pulando notificação de email para %s", config["destino"])
                continue
            try:
                mail = MIMEText(msg_text, "plain", "utf-8")
                mail["Subject"] = f"[RADIUS] Status alterado: {nome} → {new_status.upper()}"
                mail["From"] = SMTP_USER
                mail["To"] = config["destino"]
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                    server.starttls()
                    server.login(SMTP_USER, SMTP_PASS)
                    server.sendmail(SMTP_USER, config["destino"], mail.as_string())
                log.info("Email enviado para %s (cliente=%s)", config["destino"], nome)
            except Exception as e:
                log.warning("Falha ao enviar email para %s: %s", config["destino"], e)


SYNC_MAX_DURATION = int(os.environ.get("SYNC_MAX_DURATION", "600"))  # 10 min padrão


def sync_all():
    log.info("Iniciando ciclo de sincronização...")
    r = get_redis()
    try:
        conn = get_db()
    except Exception as e:
        log.error("Não foi possível conectar ao banco: %s", e)
        if r:
            r.set("sync:last_error", f"DB indisponível: {e}", ex=3600)
        return

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, nome, cpf, pppoe_login, velocidade_down, velocidade_up, status, ip "
                "FROM clientes"
            )
            clientes = cur.fetchall()

        total = len(clientes)
        atualizados = 0
        sync_start = time.time()

        for c in clientes:
            # Timeout geral: aborta se exceder SYNC_MAX_DURATION segundos
            if time.time() - sync_start > SYNC_MAX_DURATION:
                log.warning("Sync abortado: tempo máximo de %ds excedido após %d clientes.", SYNC_MAX_DURATION, atualizados)
                if r:
                    r.set("sync:last_error", f"Timeout: ciclo excedeu {SYNC_MAX_DURATION}s", ex=3600)
                break

            cpf = c["cpf"]
            contrato = consultar_sgp(cpf)
            if not contrato:
                continue

            display = contrato.get("contratoStatusDisplay", "").lower()
            novo_status = "ativo" if display == "ativo" else "suspenso"
            pppoe_login = contrato.get("contratoCentralLogin") or c["pppoe_login"]
            ip_sgp = contrato.get("servico_ip")
            ip_local = (c.get("ip") or "").strip()
            old_status = c["status"]
            changed = novo_status != old_status

            # ip_local = IP real do cliente (setado manualmente ou vindo do SGP anteriormente)
            # ip_banco = o que vai salvo no banco (sempre o IP real, nunca 10.24.x.x)
            # ip_radius = o que vai para o RADIUS (real se ativo, 10.24.x.x se suspenso)
            ip_banco = ip_local or (ip_sgp or "")

            if novo_status == "suspenso":
                ip_radius = alocar_ip_suspenso(conn)
                if changed:
                    log.info("IP de suspensão alocado para %s: %s", pppoe_login, ip_radius)
            else:
                # Ativo: usa IP setado manualmente primeiro, depois fallback para SGP
                ip_radius = ip_banco

            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE clientes
                       SET status=%s, pppoe_login=%s, ip=COALESCE(NULLIF(%s, ''), ip),
                           ultimo_sync_em=NOW(), atualizado_em=NOW()
                       WHERE id=%s""",
                    (novo_status, pppoe_login, ip_banco, c["id"]),
                )
            conn.commit()

            if pppoe_login:
                upsert_radius_user(
                    conn, pppoe_login, novo_status,
                    c["velocidade_down"], c["velocidade_up"],
                    ip_radius,
                )

            if changed:
                log.info(
                    "Cliente %s (login=%s): %s → %s",
                    cpf, pppoe_login, old_status, novo_status,
                )
                atualizados += 1
                # Enriquece o dict com dados atualizados para notificação
                cliente_notif = dict(c)
                cliente_notif["pppoe_login"] = pppoe_login
                send_notifications(conn, cliente_notif, old_status, novo_status)

        now_iso = datetime.now(timezone.utc).isoformat()
        log.info(
            "Sincronização concluída: %d/%d clientes processados, %d alterados.",
            total, total, atualizados,
        )
        if r:
            r.set("sync:last_run", now_iso, ex=86400)
            r.delete("sync:last_error")
            r.delete("online_users")  # invalida cache de sessões
    except Exception as e:
        log.error("Erro durante sincronização: %s", e)
        if r:
            r.set("sync:last_error", str(e), ex=3600)
    finally:
        conn.close()


def check_alertas_consumo(conn):
    """Verifica alertas de consumo mensal e envia notificações se ultrapassado."""
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT ac.id, ac.cliente_id, ac.limite_gb,
                       ac.notificar_webhook, ac.notificar_email,
                       ac.ultimo_alerta_em,
                       c.nome, c.pppoe_login
                FROM alertas_consumo ac
                JOIN clientes c ON c.id = ac.cliente_id
                WHERE ac.ativo = TRUE AND c.pppoe_login IS NOT NULL
            """)
            alertas = cur.fetchall()

        for alerta in alertas:
            # Só dispara uma vez por mês
            ultimo = alerta.get("ultimo_alerta_em")
            if ultimo:
                from datetime import datetime, timezone
                now = datetime.now(timezone.utc)
                if ultimo.year == now.year and ultimo.month == now.month:
                    continue

            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT COALESCE(SUM(acctinputoctets + acctoutputoctets), 0) AS total_bytes
                    FROM radacct
                    WHERE username = %s
                      AND acctstarttime >= date_trunc('month', NOW())
                """, (alerta["pppoe_login"],))
                row = cur.fetchone()

            total_bytes = int(row["total_bytes"] or 0)
            limite_bytes = float(alerta["limite_gb"]) * 1_073_741_824
            total_gb = total_bytes / 1_073_741_824

            if total_bytes >= limite_bytes:
                log.info(
                    "Alerta consumo: cliente=%s consumiu %.2f GB (limite=%.2f GB)",
                    alerta["nome"], total_gb, alerta["limite_gb"],
                )
                msg_text = (
                    f"Cliente: {alerta['nome']}\n"
                    f"Login: {alerta['pppoe_login']}\n"
                    f"Consumo este mês: {total_gb:.2f} GB\n"
                    f"Limite configurado: {alerta['limite_gb']} GB"
                )

                # Notificações
                configs = []
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    if alerta["notificar_webhook"]:
                        cur.execute("SELECT * FROM notificacoes_config WHERE tipo='webhook' AND ativo=TRUE")
                        configs += cur.fetchall()
                    if alerta["notificar_email"]:
                        cur.execute("SELECT * FROM notificacoes_config WHERE tipo='email' AND ativo=TRUE")
                        configs += cur.fetchall()

                fake_cliente = {"nome": alerta["nome"], "cpf": "", "pppoe_login": alerta["pppoe_login"]}
                for cfg in configs:
                    if cfg["tipo"] == "webhook":
                        try:
                            requests.post(cfg["destino"], json={
                                "event": "consumo_limite",
                                "cliente_nome": alerta["nome"],
                                "pppoe_login": alerta["pppoe_login"],
                                "consumo_gb": round(total_gb, 2),
                                "limite_gb": float(alerta["limite_gb"]),
                            }, timeout=5)
                        except Exception as e:
                            log.warning("Webhook alerta consumo falhou: %s", e)
                    elif cfg["tipo"] == "email" and SMTP_HOST and SMTP_USER:
                        try:
                            mail = MIMEText(msg_text, "plain", "utf-8")
                            mail["Subject"] = f"[RADIUS] Limite de consumo: {alerta['nome']}"
                            mail["From"] = SMTP_USER
                            mail["To"] = cfg["destino"]
                            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as srv:
                                srv.starttls()
                                srv.login(SMTP_USER, SMTP_PASS)
                                srv.sendmail(SMTP_USER, cfg["destino"], mail.as_string())
                        except Exception as e:
                            log.warning("Email alerta consumo falhou: %s", e)

                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE alertas_consumo SET ultimo_alerta_em=NOW() WHERE id=%s",
                        (alerta["id"],),
                    )
                conn.commit()
    except Exception as e:
        log.warning("Erro ao verificar alertas de consumo: %s", e)


OFFLINE_ALERT_DAYS = int(os.environ.get("OFFLINE_ALERT_DAYS", "0"))  # 0 = desativado


def check_clientes_offline(conn):
    """Notifica clientes ativos que não se conectam há OFFLINE_ALERT_DAYS dias."""
    if OFFLINE_ALERT_DAYS <= 0:
        return
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT c.id, c.nome, c.pppoe_login, c.cpf,
                       MAX(ra.acctstarttime) AS ultima_sessao
                FROM clientes c
                LEFT JOIN radacct ra ON ra.username = c.pppoe_login
                WHERE c.status = 'ativo'
                  AND c.pppoe_login IS NOT NULL
                GROUP BY c.id, c.nome, c.pppoe_login, c.cpf
                                HAVING MAX(ra.acctstarttime) < NOW() - (%s * INTERVAL '1 day')
                    OR MAX(ra.acctstarttime) IS NULL
            """, (OFFLINE_ALERT_DAYS,))
            offline_clientes = cur.fetchall()

        if not offline_clientes:
            return

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM notificacoes_config WHERE ativo = TRUE")
            configs = cur.fetchall()

        if not configs:
            return

        for c in offline_clientes:
            ultima = c["ultima_sessao"]
            dias_str = f"há {OFFLINE_ALERT_DAYS}+ dias" if ultima else "nunca conectou"
            log.info("Cliente offline: %s (login=%s) — %s", c["nome"], c["pppoe_login"], dias_str)
            msg_text = (
                f"Cliente: {c['nome']}\n"
                f"Login PPPoE: {c['pppoe_login']}\n"
                f"Status: ativo mas offline {dias_str}\n"
                f"Última sessão: {ultima or 'nenhuma'}"
            )
            for cfg in configs:
                if cfg["tipo"] == "webhook":
                    try:
                        requests.post(cfg["destino"], json={
                            "event": "cliente_offline",
                            "cliente_nome": c["nome"],
                            "pppoe_login": c["pppoe_login"],
                            "ultima_sessao": str(ultima) if ultima else None,
                            "dias_sem_conexao": OFFLINE_ALERT_DAYS,
                        }, timeout=5)
                    except Exception as e:
                        log.warning("Webhook offline falhou: %s", e)
                elif cfg["tipo"] == "email" and SMTP_HOST and SMTP_USER:
                    try:
                        mail = MIMEText(msg_text, "plain", "utf-8")
                        mail["Subject"] = f"[RADIUS] Cliente offline: {c['nome']}"
                        mail["From"] = SMTP_USER
                        mail["To"] = cfg["destino"]
                        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as srv:
                            srv.starttls()
                            srv.login(SMTP_USER, SMTP_PASS)
                            srv.sendmail(SMTP_USER, cfg["destino"], mail.as_string())
                    except Exception as e:
                        log.warning("Email offline falhou: %s", e)

        log.info("Alerta offline: %d cliente(s) sem conexão há %d+ dias.", len(offline_clientes), OFFLINE_ALERT_DAYS)
    except Exception as e:
        log.warning("Erro ao verificar clientes offline: %s", e)


# =============================================================================
# Telegram
# =============================================================================

GENIEACS_NBI_URL = os.environ.get("GENIEACS_NBI_URL", "http://genieacs-nbi:7557").rstrip("/")
CPE_POLL_INTERVAL = int(os.environ.get("CPE_POLL_INTERVAL", "60"))  # segundos


def _get_alerta_config(conn, chave, default=""):
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT valor FROM alertas_config WHERE chave=%s", (chave,))
            row = cur.fetchone()
            return row[0] if row else default
    except Exception:
        return default


from notifier import TelegramNotifier
notifier = TelegramNotifier(get_db, get_redis)


def telegram_send(conn, msg, dedup_key=None, severity="warning", cooldown=300):
    """
    Wrapper compatível com callsites antigos.
    Para alertas firing/resolved, prefira notifier.fire() / notifier.resolve().
    """
    event_type = (dedup_key or "legacy").split(":", 1)[0]
    notifier.send(event_type, msg, dedup_key=dedup_key,
                  severity=severity, cooldown=cooldown)


def _cpe_log_event(conn, cpe_id, event_type, detail=None):
    try:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO cpe_events (cpe_id, event_type, detail) VALUES (%s, %s, %s)",
                (cpe_id, event_type, json.dumps(detail or {}))
            )
        conn.commit()
    except Exception as e:
        log.warning("cpe_log_event error: %s", e)


def _abrir_chamado(conn, cpe_id, cliente_id, tipo, descricao):
    """Abre chamado se não houver um aberto do mesmo tipo para este CPE."""
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id FROM chamados
                WHERE cpe_id=%s AND tipo=%s AND status='aberto'
                LIMIT 1
            """, (cpe_id, tipo))
            if cur.fetchone():
                return  # já existe chamado aberto
            cur.execute("""
                INSERT INTO chamados (cpe_id, cliente_id, tipo, descricao)
                VALUES (%s, %s, %s, %s)
            """, (cpe_id, cliente_id, tipo, descricao))
        conn.commit()
        log.info("Chamado aberto: cpe_id=%s tipo=%s", cpe_id, tipo)
    except Exception as e:
        log.warning("_abrir_chamado error: %s", e)


def _fechar_chamados(conn, cpe_id, tipo):
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE chamados SET status='resolvido', resolvido_em=NOW(), atualizado_em=NOW()
                WHERE cpe_id=%s AND tipo=%s AND status='aberto'
            """, (cpe_id, tipo))
        conn.commit()
    except Exception as e:
        log.warning("_fechar_chamados error: %s", e)


def _gv_raw(obj, path):
    """Navega JSON GenieACS por path pontilhado."""
    parts = path.split(".")
    cur = obj
    for p in parts:
        if not isinstance(cur, dict): return None
        cur = cur.get(p)
    if isinstance(cur, dict): return cur.get("_value")
    return cur


def check_cpe_status(conn):
    """Monitora CPEs via GenieACS: detecta online/offline, mudança de IP, Rx crítico."""
    try:
        r = requests.get(f"{GENIEACS_NBI_URL}/devices?limit=500", timeout=10)
        r.raise_for_status()
        devices = r.json()
    except Exception as e:
        log.warning("GenieACS poll error: %s", e)
        return

    try:
        rx_min = float(_get_alerta_config(conn, "rx_power_min", "-27"))
        offline_min = int(_get_alerta_config(conn, "cpe_offline_minutos", "15"))
    except Exception:
        rx_min = -27.0; offline_min = 15

    # Mapa genieacs_id → dados locais
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT cpe.id, cpe.genieacs_id, cpe.online, cpe.ip_wan, cpe.rx_power,
                   cpe.cliente_id, cpe.ultima_conexao, c.nome AS cliente_nome
            FROM cpe_devices cpe
            LEFT JOIN clientes c ON c.id = cpe.cliente_id
            WHERE cpe.genieacs_id IS NOT NULL
        """)
        cpes_db = {row["genieacs_id"]: row for row in cur.fetchall()}

    from datetime import timezone as tz
    now = datetime.now(tz.utc)

    for dev in devices:
        genieacs_id = dev.get("_id", "")
        if genieacs_id not in cpes_db:
            continue

        cpe = cpes_db[genieacs_id]
        cpe_id     = cpe["id"]
        cliente_id = cpe["cliente_id"]
        nome       = cpe["cliente_nome"] or "?"

        # Online = lastInform presente e recente (< offline_min minutos)
        last_inform_str = dev.get("_lastInform")
        now_online = False
        if last_inform_str:
            try:
                li = datetime.fromisoformat(last_inform_str.replace("Z", "+00:00"))
                diff_min = (now - li).total_seconds() / 60
                now_online = diff_min < offline_min
            except Exception:
                now_online = True

        was_online = bool(cpe["online"])

        # IP WAN atual
        ip_now = (
            _gv_raw(dev, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANPPPConnection.1.ExternalIPAddress")
            or _gv_raw(dev, "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress")
            or ""
        )
        ip_old = cpe["ip_wan"] or ""

        # Rx Power
        rx_now = (
            _gv_raw(dev, "InternetGatewayDevice.WANDevice.1.X_GponInterafceConfig.RXPower")  # Intelbras AX1800
            or _gv_raw(dev, "InternetGatewayDevice.WANDevice.1.X_FH_GponInterfaceConfig.RXPower")  # FiberHome
            or _gv_raw(dev, "InternetGatewayDevice.WANDevice.1.X_PON_RxPower")  # genérico
            or _gv_raw(dev, "Device.Optical.Interface.1.CurrentPower")  # TR-181
        )
        if rx_now is not None:
            try: rx_now = float(rx_now)
            except Exception: rx_now = None

        # --- Detecta mudanças ---
        updates = {"online": now_online, "atualizado_em": "NOW()"}
        if now_online:
            updates["ultima_conexao"] = now.isoformat()
        if ip_now:
            updates["ip_wan"] = ip_now
        if rx_now is not None:
            updates["rx_power"] = rx_now

        with conn.cursor() as cur:
            cur.execute("""
                UPDATE cpe_devices SET online=%s, ip_wan=COALESCE(%s, ip_wan),
                    rx_power=COALESCE(%s, rx_power),
                    ultima_conexao=CASE WHEN %s THEN NOW() ELSE ultima_conexao END,
                    atualizado_em=NOW()
                WHERE id=%s
            """, (now_online, ip_now or None, rx_now, now_online, cpe_id))
        conn.commit()

        # Evento: ficou online
        if now_online and not was_online:
            _cpe_log_event(conn, cpe_id, "online", {"ip": ip_now})
            _fechar_chamados(conn, cpe_id, "cpe_offline")
            telegram_send(conn,
                f"✅ <b>CPE Online</b>\nCliente: {nome}\nIP WAN: {ip_now or '—'}")
            log.info("CPE online: %s (%s)", nome, genieacs_id)

        # Evento: ficou offline
        elif not now_online and was_online:
            _cpe_log_event(conn, cpe_id, "offline", {})
            _abrir_chamado(conn, cpe_id, cliente_id, "cpe_offline",
                f"CPE do cliente {nome} ficou offline.")
            telegram_send(conn,
                f"🔴 <b>CPE Offline</b>\nCliente: {nome}\nÚltima conexão: {cpe['ultima_conexao'] or '—'}")
            log.info("CPE offline: %s (%s)", nome, genieacs_id)

        # Evento: IP mudou
        if now_online and ip_now and ip_old and ip_now != ip_old:
            _cpe_log_event(conn, cpe_id, "ip_change", {"ip_anterior": ip_old, "ip_novo": ip_now})
            log.info("CPE IP mudou: %s %s → %s", nome, ip_old, ip_now)

        # Evento: Rx crítico
        if rx_now is not None and rx_now < rx_min:
            old_rx = cpe["rx_power"]
            # Só alerta se piorou ou não havia alerta anterior
            if old_rx is None or old_rx >= rx_min:
                _cpe_log_event(conn, cpe_id, "rx_alert", {"rx_power": rx_now, "limiar": rx_min})
                _abrir_chamado(conn, cpe_id, cliente_id, "rx_critico",
                    f"Rx Power crítico: {rx_now:.1f} dBm (limiar {rx_min} dBm)")
                telegram_send(conn,
                    f"⚠️ <b>Sinal Óptico Crítico</b>\nCliente: {nome}\nRx Power: {rx_now:.1f} dBm (limiar: {rx_min} dBm)")
                log.info("Rx crítico: %s %.1f dBm", nome, rx_now)
        elif rx_now is not None and rx_now >= rx_min:
            _fechar_chamados(conn, cpe_id, "rx_critico")


def check_clientes_sem_conexao(conn):
    """Detecta clientes ativos sem nenhuma sessão RADIUS e abre chamado."""
    try:
        offline_min = int(_get_alerta_config(conn, "cpe_offline_minutos", "15"))
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT c.id, c.nome, c.pppoe_login
                FROM clientes c
                WHERE c.status = 'ativo' AND c.pppoe_login IS NOT NULL
                  AND NOT EXISTS (
                    SELECT 1 FROM radacct ra
                    WHERE ra.username = c.pppoe_login
                      AND ra.acctstarttime > NOW() - (%s * INTERVAL '1 minute')
                      AND ra.acctstoptime IS NULL
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM chamados ch
                    WHERE ch.cliente_id = c.id AND ch.tipo='sem_conexao' AND ch.status='aberto'
                    AND ch.criado_em > NOW() - INTERVAL '4 hours'
                  )
            """, (offline_min * 10,))  # sem sessão ativa por 10x o limiar
            sem_sessao = cur.fetchall()

        for c in sem_sessao:
            # Verifica se realmente nunca teve sessão ou parou há muito
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT MAX(acctstarttime) FROM radacct WHERE username=%s
                """, (c["pppoe_login"],))
                ultima = cur.fetchone()[0]

            if ultima is None:
                continue  # nunca conectou — não é incidente

            from datetime import timezone as tz
            diff_h = (datetime.now(tz.utc) - ultima.replace(tzinfo=tz.utc)).total_seconds() / 3600
            if diff_h < 1:
                continue  # desconectou há menos de 1h — normal

            _abrir_chamado(conn, None, c["id"], "sem_conexao",
                f"Cliente {c['nome']} sem sessão RADIUS há {diff_h:.1f}h.")
            telegram_send(conn,
                f"📵 <b>Cliente Sem Conexão</b>\nCliente: {c['nome']}\nLogin: {c['pppoe_login']}\nSem sessão há {diff_h:.1f}h")
    except Exception as e:
        log.warning("check_clientes_sem_conexao error: %s", e)


if __name__ == "__main__":
    log.info("Serviço de sync iniciado. Intervalo: %ds | CPE poll: %ds", SYNC_INTERVAL, CPE_POLL_INTERVAL)
    time.sleep(15)

    from health_checks import run_health_checks, heartbeat_sync_start

    cpe_last_poll = 0
    last_cycle_started_at = None

    while True:
        cycle_started_at = time.time()
        r_global = get_redis()
        heartbeat_sync_start(r_global)

        sync_all()
        try:
            conn = get_db()
            check_alertas_consumo(conn)
            check_clientes_offline(conn)

            # CPE monitoring no próprio loop (sem thread extra)
            if time.time() - cpe_last_poll >= CPE_POLL_INTERVAL:
                check_cpe_status(conn)
                check_clientes_sem_conexao(conn)
                cpe_last_poll = time.time()

            # Health checks de infra (NAS, serviços externos, FreeRADIUS, lag de sync)
            run_health_checks(conn, r_global, notifier, last_cycle_started_at)

            conn.close()
        except Exception as e:
            log.warning("Erro ao checar alertas: %s", e)

        last_cycle_started_at = cycle_started_at
        time.sleep(SYNC_INTERVAL)
