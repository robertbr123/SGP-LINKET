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
import requests
import psycopg2
import psycopg2.extras
from datetime import datetime, timezone
from email.mime.text import MIMEText


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
        else:
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
            # Mantém IP cadastrado manualmente no painel; só usa IP do SGP se local estiver vazio
            ip_efetivo = ip_local or (ip_sgp or "")
            old_status = c["status"]
            changed = novo_status != old_status

            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE clientes
                       SET status=%s, pppoe_login=%s, ip=COALESCE(NULLIF(ip, ''), %s),
                           ultimo_sync_em=NOW(), atualizado_em=NOW()
                       WHERE id=%s""",
                    (novo_status, pppoe_login, ip_sgp, c["id"]),
                )
            conn.commit()

            if pppoe_login:
                upsert_radius_user(
                    conn, pppoe_login, novo_status,
                    c["velocidade_down"], c["velocidade_up"],
                    ip_efetivo,
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


if __name__ == "__main__":
    log.info("Serviço de sync iniciado. Intervalo: %ds", SYNC_INTERVAL)
    if OFFLINE_ALERT_DAYS > 0:
        log.info("Alertas offline ativados: clientes sem conexão há %d+ dias serão notificados.", OFFLINE_ALERT_DAYS)
    time.sleep(15)
    while True:
        sync_all()
        try:
            conn = get_db()
            check_alertas_consumo(conn)
            check_clientes_offline(conn)
            conn.close()
        except Exception as e:
            log.warning("Erro ao checar alertas: %s", e)
        time.sleep(SYNC_INTERVAL)
