"""
Bot interativo do Telegram — long polling.

Recebe comandos do chat configurado em alertas_config.telegram_chat_id e
despacha para handlers em commands.py. Estado do offset persistido em Redis.

Segurança:
- Só responde mensagens vindas do chat_id configurado (whitelist única)
- Comandos destrutivos auditados em audit_log
- /desconectar e /reiniciar_cpe loggados antes de executar
"""
import os
import time
import json
import logging
from datetime import datetime, timezone

import requests
import psycopg2
import psycopg2.extras
import redis as redis_lib

from notifier import TelegramNotifier
from commands import dispatch, send_message

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"bot","msg":"%(message)s"}',
)
log = logging.getLogger("bot")


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


def get_telegram_config():
    """Lê token + chat_id da tabela alertas_config. Retorna (token, chat_id) ou (None, None)."""
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT chave, valor FROM alertas_config "
                "WHERE chave IN ('telegram_bot_token','telegram_chat_id','telegram_enabled')"
            )
            cfg = {r[0]: r[1] for r in cur.fetchall()}
        conn.close()
        if cfg.get("telegram_enabled", "false").lower() != "true":
            return None, None
        return cfg.get("telegram_bot_token") or None, cfg.get("telegram_chat_id") or None
    except Exception as e:
        log.warning("Falha ao ler config Telegram: %s", e)
        return None, None


def get_updates(token, offset, timeout=30):
    """Long polling. Bloqueia até timeout ou chegada de update."""
    try:
        r = requests.get(
            f"https://api.telegram.org/bot{token}/getUpdates",
            params={"offset": offset, "timeout": timeout, "allowed_updates": json.dumps(["message"])},
            timeout=timeout + 10,
        )
        if not r.ok:
            log.warning("getUpdates HTTP %s: %s", r.status_code, r.text[:200])
            return []
        data = r.json()
        return data.get("result", []) if data.get("ok") else []
    except requests.exceptions.Timeout:
        return []
    except Exception as e:
        log.warning("getUpdates error: %s", e)
        return []


def handle_update(update, token, allowed_chat_id, notifier):
    msg = update.get("message")
    if not msg:
        return

    chat_id = str(msg.get("chat", {}).get("id", ""))
    text = (msg.get("text") or "").strip()
    sender = msg.get("from", {})
    sender_label = sender.get("username") or sender.get("first_name") or f"id:{sender.get('id')}"

    # Whitelist: só responde no chat configurado
    if chat_id != str(allowed_chat_id):
        log.warning(
            "Ignorando mensagem de chat não-autorizado: chat_id=%s (autorizado=%s) sender=%s",
            chat_id, allowed_chat_id, sender_label,
        )
        return

    if not text.startswith("/"):
        return

    log.info("comando recebido: '%s' de %s", text[:80], sender_label)

    try:
        dispatch(
            text=text,
            chat_id=chat_id,
            sender=sender_label,
            token=token,
            get_db=get_db,
            get_redis=get_redis,
            notifier=notifier,
        )
    except Exception as e:
        log.exception("dispatch error: %s", e)
        try:
            send_message(token, chat_id,
                         f"❌ <b>Erro ao processar comando</b>\n<code>{type(e).__name__}: {e}</code>")
        except Exception:
            pass


def main():
    log.info("Bot iniciado")
    time.sleep(10)  # aguarda postgres/redis estabilizarem após start

    notifier = TelegramNotifier(get_db, get_redis)

    while True:
        token, allowed_chat_id = get_telegram_config()
        if not token or not allowed_chat_id:
            log.info("Aguardando configuração de Telegram (token/chat_id/enabled)...")
            time.sleep(30)
            continue

        # Offset persistido em Redis
        r = get_redis()
        try:
            offset = int(r.get("telegram:bot:offset") or 0) if r else 0
        except Exception:
            offset = 0

        updates = get_updates(token, offset, timeout=30)

        for update in updates:
            update_id = update.get("update_id", 0)
            try:
                handle_update(update, token, allowed_chat_id, notifier)
            finally:
                if r:
                    try: r.set("telegram:bot:offset", update_id + 1)
                    except Exception: pass


if __name__ == "__main__":
    main()
