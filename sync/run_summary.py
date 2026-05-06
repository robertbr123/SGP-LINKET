"""
Dispara um dos resumos diários imediatamente (sem esperar a hora agendada).
Útil para teste e para "puxar resumo agora" sob demanda.

Uso:
    docker exec radius_sync python run_summary.py morning
    docker exec radius_sync python run_summary.py shift
    docker exec radius_sync python run_summary.py heartbeat
"""
import os
import sys
import psycopg2
import redis as redis_lib

from notifier import TelegramNotifier
from summaries import _morning_summary, _shift_summary, _heartbeat_message


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
    if len(sys.argv) < 2 or sys.argv[1] not in ("morning", "shift", "heartbeat"):
        print("uso: python run_summary.py [morning|shift|heartbeat]", file=sys.stderr)
        sys.exit(1)

    tipo = sys.argv[1]
    notifier = TelegramNotifier(get_db, get_redis)
    conn = get_db()
    try:
        r = get_redis()
        if tipo == "morning":
            msg = _morning_summary(conn)
            event = "summary_morning"
            # Anexa análise IA (mesmo comportamento do agendador automático)
            try:
                from ai_summary import generate_morning_analysis
                ai_text = generate_morning_analysis(conn)
                if ai_text:
                    msg += ai_text
                    print("[run_summary] análise IA anexada", file=sys.stderr)
                else:
                    print("[run_summary] IA retornou None — sem análise", file=sys.stderr)
            except ImportError:
                print("[run_summary] ai_summary indisponível", file=sys.stderr)
            except Exception as e:
                print(f"[run_summary] erro IA: {e}", file=sys.stderr)
        elif tipo == "shift":
            msg = _shift_summary(conn)
            event = "summary_shift"
            try:
                from ai_summary import generate_shift_analysis
                ai_text = generate_shift_analysis(conn)
                if ai_text:
                    msg += ai_text
                    print("[run_summary] análise IA anexada", file=sys.stderr)
                else:
                    print("[run_summary] IA retornou None — sem análise", file=sys.stderr)
            except Exception as e:
                print(f"[run_summary] erro IA: {e}", file=sys.stderr)
        else:
            msg = _heartbeat_message(conn, r)
            event = "summary_heartbeat"

        ok = notifier.send(event, msg, severity="info", cooldown=0, force=True)
        print("ok — enviado" if ok else "falhou", file=sys.stderr)
    finally:
        conn.close()
