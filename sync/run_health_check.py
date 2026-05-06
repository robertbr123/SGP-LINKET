"""
Invocador standalone dos health checks. Útil para testar manualmente
sem esperar o ciclo do sync (que pode levar minutos com muitos clientes).

Uso:
    docker exec radius_sync python run_health_check.py

Roda 1 vez todos os checks de infra, dispara alertas se necessário e sai.
"""
import os
import sys
import psycopg2

import redis as redis_lib

from notifier import TelegramNotifier
from health_checks import run_health_checks


def get_db():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "postgres"),
        dbname=os.environ.get("DB_NAME", "radius"),
        user=os.environ.get("DB_USER", "radius"),
        password=os.environ.get("DB_PASS", "radiuspassword"),
    )


def get_redis():
    try:
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


if __name__ == "__main__":
    notifier = TelegramNotifier(get_db, get_redis)
    conn = get_db()
    try:
        run_health_checks(conn, get_redis(), notifier)
        print("ok — health checks executados, veja Telegram + alert_state", file=sys.stderr)
    finally:
        conn.close()
