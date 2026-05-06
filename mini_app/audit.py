"""
Audit log local do mini_app — escreve em audit_log do Postgres.
Não envia Telegram (o painel já está dentro do Telegram, seria redundante).
"""
import json
import logging

log = logging.getLogger("miniapp.audit")


def log_audit(get_db, app_user, action, target_type=None, target_id=None, detail=None):
    try:
        nome = f"miniapp:{app_user.get('nome') or app_user.get('telegram_user_id')}"
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_log
                    (ts, usuario_nome, ip, action, target_type, target_id, detail)
                VALUES (NOW(), %s, %s, %s, %s, %s, %s)
            """, (
                nome[:80],
                "mini-app",
                action,
                target_type,
                str(target_id) if target_id is not None else None,
                json.dumps(detail or {}, default=str),
            ))
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("audit insert failed: %s", e)
