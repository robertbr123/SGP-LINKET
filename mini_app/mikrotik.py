"""
Coleta de sessões PPPoE ativas via API MikroTik (paralelo).
Igual ao usado pelo bot — replicado aqui pra não criar dependência cruzada.
"""
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import psycopg2.extras

try:
    import librouteros
    MIKROTIK_AVAILABLE = True
except ImportError:
    MIKROTIK_AVAILABLE = False

log = logging.getLogger("miniapp.mikrotik")


def _probe_nas_active(nas):
    if not MIKROTIK_AVAILABLE:
        return []
    try:
        api = librouteros.connect(
            host=nas["nasname"],
            username=nas["mikrotik_user"],
            password=nas["mikrotik_pass"],
            port=int(nas.get("mikrotik_port") or 8728),
            timeout=6,
        )
    except Exception as e:
        log.warning("mt connect %s: %s", nas["nasname"], e)
        return []

    sessoes = []
    try:
        try:
            ppp = list(api("/ppp/active/print"))
        except Exception:
            ppp = []
        for s in ppp:
            sessoes.append({
                "username":  s.get("name", ""),
                "ip":        s.get("address", ""),
                "uptime":    s.get("uptime", ""),
                "service":   s.get("service", ""),
                "caller":    s.get("caller-id", ""),
                "nas_label": nas.get("shortname") or nas["nasname"],
                "nas_id":    nas["id"],
            })
    finally:
        try: api.close()
        except Exception: pass
    return sessoes


def online_via_mikrotik(get_db):
    """Retorna lista de sessões ativas em todos os NAS, ou None se nenhum NAS configurado."""
    if not MIKROTIK_AVAILABLE:
        return None

    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, nasname, shortname, mikrotik_user, mikrotik_pass, mikrotik_port
                  FROM nas
                 WHERE mikrotik_user IS NOT NULL AND mikrotik_pass IS NOT NULL
                   AND mikrotik_pass != ''
            """)
            nas_list = cur.fetchall()
    finally:
        conn.close()

    if not nas_list:
        return None

    sessoes = []
    with ThreadPoolExecutor(max_workers=min(8, len(nas_list))) as pool:
        futs = {pool.submit(_probe_nas_active, n): n for n in nas_list}
        for fut in as_completed(futs, timeout=20):
            try:
                sessoes.extend(fut.result() or [])
            except Exception:
                pass
    return sessoes


def online_logins_set(get_db):
    """Set de pppoe_logins online (para cruzar com clientes rapidamente)."""
    sessoes = online_via_mikrotik(get_db)
    if sessoes is None:
        # Fallback radacct
        conn = get_db()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT username FROM radacct WHERE acctstoptime IS NULL")
                return {r[0] for r in cur.fetchall()}
        finally:
            conn.close()
    return {s["username"] for s in sessoes if s.get("username")}
