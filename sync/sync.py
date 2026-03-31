"""
Serviço de sincronização automática com o SGP.
Roda em loop consultando todos os clientes cadastrados e atualiza
o status no banco + tabelas do FreeRADIUS.
"""
import os
import time
import logging
import requests
import psycopg2
import psycopg2.extras

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [SYNC] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

SGP_URL = os.environ.get("SGP_URL", "https://linknetam.sgp.net.br/api/ura/consultacliente/")
SGP_TOKEN = os.environ.get("SGP_TOKEN", "8e6523a9-2c7e-43de-888b-555da380a8fd")
SGP_APP = os.environ.get("SGP_APP", "bot")
SYNC_INTERVAL = int(os.environ.get("SYNC_INTERVAL", "300"))  # segundos


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
        log.debug("SGP resposta para cpf=%s: %s", cpf, data)
        contratos = data.get("contratos", [])
        if contratos:
            return contratos[0]
        # Resposta OK mas sem contratos — loga o corpo completo para depuração
        log.warning("SGP retornou sem contratos para cpf=%s. Resposta: %s", cpf, data)
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


def sync_all():
    log.info("Iniciando ciclo de sincronização...")
    try:
        conn = get_db()
    except Exception as e:
        log.error("Não foi possível conectar ao banco: %s", e)
        return

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id, cpf, pppoe_login, velocidade_down, velocidade_up, status FROM clientes")
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

            changed = novo_status != c["status"]

            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE clientes SET status=%s, pppoe_login=%s,
                       ip=COALESCE(%s, ip), atualizado_em=NOW() WHERE id=%s""",
                    (novo_status, pppoe_login, ip_sgp, c["id"]),
                )
            conn.commit()

            if pppoe_login:
                upsert_radius_user(conn, pppoe_login, novo_status,
                                   c["velocidade_down"], c["velocidade_up"],
                                   ip_sgp or "")

            if changed:
                log.info("Cliente %s (login=%s): %s → %s",
                         cpf, pppoe_login, c["status"], novo_status)
                atualizados += 1

        log.info("Sincronização concluída: %d/%d clientes, %d alterados.",
                 total, total, atualizados)
    except Exception as e:
        log.error("Erro durante sincronização: %s", e)
    finally:
        conn.close()


if __name__ == "__main__":
    log.info("Serviço de sync iniciado. Intervalo: %ds", SYNC_INTERVAL)
    # Aguarda o banco subir
    time.sleep(15)
    while True:
        sync_all()
        time.sleep(SYNC_INTERVAL)
