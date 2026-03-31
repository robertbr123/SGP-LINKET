"""
Serviço de sincronização automática com o SGP.
Roda em loop consultando todos os clientes cadastrados e atualiza
o status no banco + tabelas do FreeRADIUS.
Envia notificações (email/webhook) quando o status muda.
"""
import os
import time
import smtplib
import logging
import requests
import psycopg2
import psycopg2.extras
from email.mime.text import MIMEText

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SYNC] %(levelname)s %(message)s",
)
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


def sync_all():
    log.info("Iniciando ciclo de sincronização...")
    try:
        conn = get_db()
    except Exception as e:
        log.error("Não foi possível conectar ao banco: %s", e)
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

        for c in clientes:
            cpf = c["cpf"]
            contrato = consultar_sgp(cpf)
            if not contrato:
                continue

            display = contrato.get("contratoStatusDisplay", "").lower()
            novo_status = "ativo" if display == "ativo" else "suspenso"
            pppoe_login = contrato.get("contratoCentralLogin") or c["pppoe_login"]
            ip_sgp = contrato.get("servico_ip")
            old_status = c["status"]
            changed = novo_status != old_status

            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE clientes
                       SET status=%s, pppoe_login=%s, ip=COALESCE(%s, ip),
                           ultimo_sync_em=NOW(), atualizado_em=NOW()
                       WHERE id=%s""",
                    (novo_status, pppoe_login, ip_sgp, c["id"]),
                )
            conn.commit()

            if pppoe_login:
                upsert_radius_user(
                    conn, pppoe_login, novo_status,
                    c["velocidade_down"], c["velocidade_up"],
                    ip_sgp or c.get("ip") or "",
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

        log.info(
            "Sincronização concluída: %d/%d clientes processados, %d alterados.",
            total, total, atualizados,
        )
    except Exception as e:
        log.error("Erro durante sincronização: %s", e)
    finally:
        conn.close()


if __name__ == "__main__":
    log.info("Serviço de sync iniciado. Intervalo: %ds", SYNC_INTERVAL)
    time.sleep(15)
    while True:
        sync_all()
        time.sleep(SYNC_INTERVAL)
