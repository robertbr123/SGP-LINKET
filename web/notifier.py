"""
Notifier centralizado de alertas Telegram.

Recursos:
- Severidade (info, warning, critical) com prefixo no emoji
- Janelas de manutenção (silencia alertas por escopo)
- Cooldown anti-flood via Redis (TTL curto)
- Estado firing/resolved em alert_state (durável, Postgres)
- Auto-resolve com mensagem "voltou ao normal"

Uso:
    notifier = TelegramNotifier(get_db, get_redis)
    notifier.fire("nas_down:5",  severity="critical",
                  msg="<b>NAS Mikrotik 5 inacessível</b>")
    notifier.resolve("nas_down:5",
                     msg="<b>NAS Mikrotik 5 voltou</b>")

Compatibilidade:
- Versão idêntica em web/notifier.py e sync/notifier.py
- Não introduz dependências novas (só requests + psycopg2 + redis já em uso)
"""
import json
import logging
from datetime import datetime, timezone

import requests

log = logging.getLogger("notifier")

SEVERITY_EMOJI = {
    "info":     "ℹ️",
    "warning":  "⚠️",
    "critical": "🔴",
    "ok":       "✅",
    "audit":    "🔐",
}


class TelegramNotifier:
    def __init__(self, db_factory, redis_factory=None):
        """
        db_factory: callable que retorna conexão psycopg2 (get_db)
        redis_factory: callable opcional que retorna client Redis (get_redis)
        """
        self._db = db_factory
        self._redis = redis_factory

    # --------------------------------------------------------- internal helpers

    def _get_cfg(self, conn, chave, default=""):
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT valor FROM alertas_config WHERE chave=%s", (chave,))
                row = cur.fetchone()
                return row[0] if row else default
        except Exception:
            return default

    def _enabled(self, conn):
        return self._get_cfg(conn, "telegram_enabled", "false").lower() == "true"

    def _credentials(self, conn):
        token   = self._get_cfg(conn, "telegram_bot_token", "")
        chat_id = self._get_cfg(conn, "telegram_chat_id", "")
        return token, chat_id

    def _in_maintenance(self, conn, dedup_key, event_type):
        """True se houver janela de manutenção ativa cobrindo este alerta."""
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT escopo FROM maintenance_window
                    WHERE inicio <= NOW() AND fim >= NOW()
                """)
                escopos = [r[0] for r in cur.fetchall()]
        except Exception:
            return False

        for esc in escopos:
            if esc == "all":
                return True
            if esc == f"event:{event_type}":
                return True
            if dedup_key and esc == dedup_key:
                return True
        return False

    def _cooldown_active(self, dedup_key, cooldown_seconds):
        """Usa Redis SET NX EX para impedir reenvios em janela curta."""
        if not self._redis or not dedup_key or cooldown_seconds <= 0:
            return False
        try:
            r = self._redis()
            if not r:
                return False
            key = f"notifier:cooldown:{dedup_key}"
            # SET com NX só grava se não existir; se já existe, está em cooldown
            ok = r.set(key, "1", nx=True, ex=cooldown_seconds)
            return not ok
        except Exception:
            return False

    def _record_state(self, conn, dedup_key, event_type, severity, firing, msg):
        if not dedup_key:
            return
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO alert_state
                        (dedup_key, event_type, severity, firing,
                         primeira_vez, ultima_vez, last_sent_at, last_msg, count_total)
                    VALUES (%s, %s, %s, %s, NOW(), NOW(), NOW(), %s, 1)
                    ON CONFLICT (dedup_key) DO UPDATE SET
                        event_type   = EXCLUDED.event_type,
                        severity     = EXCLUDED.severity,
                        firing       = EXCLUDED.firing,
                        ultima_vez   = NOW(),
                        last_sent_at = NOW(),
                        last_msg     = EXCLUDED.last_msg,
                        count_total  = alert_state.count_total + 1
                """, (dedup_key, event_type, severity, firing, msg))
            conn.commit()
        except Exception as e:
            log.warning("alert_state record failed: %s", e)

    def _was_firing(self, conn, dedup_key):
        if not dedup_key:
            return False
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT firing FROM alert_state WHERE dedup_key = %s",
                    (dedup_key,),
                )
                row = cur.fetchone()
                return bool(row and row[0])
        except Exception:
            return False

    def _send_http(self, token, chat_id, text):
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        try:
            r = requests.post(
                url,
                json={
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                },
                timeout=8,
            )
            if not r.ok:
                log.warning("telegram api error: %s %s", r.status_code, r.text[:200])
            return r.ok
        except Exception as e:
            log.warning("telegram send error: %s", e)
            return False

    def _format(self, severity, msg):
        emoji = SEVERITY_EMOJI.get(severity, "")
        ts = datetime.now(timezone.utc).astimezone().strftime("%d/%m %H:%M")
        if emoji and not msg.startswith(emoji):
            return f"{emoji} {msg}\n<i>{ts}</i>"
        return f"{msg}\n<i>{ts}</i>"

    # --------------------------------------------------------- public API

    def send(self, event_type, msg, dedup_key=None, severity="info",
             cooldown=300, force=False):
        """
        Envio one-shot (sem firing/resolved). Útil para auditoria, logins, eventos pontuais.

        force=True ignora cooldown (mas ainda respeita manutenção).
        Retorna True se enviou, False se foi suprimido.
        """
        conn = self._db()
        try:
            if not force and not self._enabled(conn):
                return False
            if not force and self._in_maintenance(conn, dedup_key, event_type):
                log.info("notifier: suprimido por manutenção (%s)", event_type)
                return False
            if not force and self._cooldown_active(dedup_key, cooldown):
                log.info("notifier: suprimido por cooldown (%s)", dedup_key or event_type)
                return False

            token, chat_id = self._credentials(conn)
            if not token or not chat_id:
                return False

            text = self._format(severity, msg)
            ok = self._send_http(token, chat_id, text)
            if ok and dedup_key:
                self._record_state(conn, dedup_key, event_type, severity, True, msg)
            return ok
        finally:
            try: conn.close()
            except Exception: pass

    def fire(self, dedup_key, msg, event_type=None, severity="warning", cooldown=300):
        """
        Alerta de incidente (firing). Idempotente:
        - Primeira vez: envia
        - Repetido dentro do cooldown: suprime
        - Repetido após cooldown: re-envia (escalada)
        """
        if not event_type:
            event_type = dedup_key.split(":", 1)[0]
        return self.send(event_type, msg, dedup_key=dedup_key,
                         severity=severity, cooldown=cooldown)

    def resolve(self, dedup_key, msg=None, event_type=None):
        """
        Marca incidente como resolvido. Só envia "voltou ao normal" se houver
        registro firing prévio em alert_state. Sem registro, não faz nada.
        """
        conn = self._db()
        try:
            if not self._was_firing(conn, dedup_key):
                return False

            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE alert_state
                       SET firing = FALSE, ultima_vez = NOW()
                     WHERE dedup_key = %s
                """, (dedup_key,))
            conn.commit()

            if not self._enabled(conn):
                return False
            if self._in_maintenance(conn, dedup_key, event_type or dedup_key.split(":", 1)[0]):
                return False

            token, chat_id = self._credentials(conn)
            if not token or not chat_id:
                return False

            text = self._format("ok", msg or f"<b>Resolvido:</b> {dedup_key}")
            return self._send_http(token, chat_id, text)
        finally:
            try: conn.close()
            except Exception: pass

    # --------------------------------------------------------- janelas de manutenção

    def silence(self, conn, minutos, escopo="all", motivo=None, criado_por=None):
        """Cria janela de manutenção e retorna o id."""
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO maintenance_window (inicio, fim, escopo, motivo, criado_por)
                VALUES (NOW(), NOW() + (%s * INTERVAL '1 minute'), %s, %s, %s)
                RETURNING id
            """, (int(minutos), escopo, motivo, criado_por))
            new_id = cur.fetchone()[0]
        conn.commit()
        return new_id

    def list_active_silences(self, conn):
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, inicio, fim, escopo, motivo, criado_por
                  FROM maintenance_window
                 WHERE inicio <= NOW() AND fim >= NOW()
              ORDER BY fim DESC
            """)
            return cur.fetchall()
