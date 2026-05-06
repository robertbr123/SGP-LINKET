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


def probe_nas_metrics(nas):
    """Coleta CPU/mem/uptime/temp + contagem de sessões PPPoE de UM NAS."""
    if not MIKROTIK_AVAILABLE:
        return {"online": False, "error": "librouteros indisponível"}
    try:
        api = librouteros.connect(
            host=nas["nasname"],
            username=nas["mikrotik_user"],
            password=nas["mikrotik_pass"],
            port=int(nas.get("mikrotik_port") or 8728),
            timeout=6,
        )
    except Exception as e:
        return {"online": False, "error": str(e)}

    try:
        try:
            res = list(api("/system/resource/print"))[0]
        except Exception:
            res = {}
        try:
            ppp = list(api("/ppp/active/print"))
            sessions = len(ppp)
        except Exception:
            sessions = None
        try:
            health = list(api("/system/health/print"))
        except Exception:
            health = []
    finally:
        try: api.close()
        except Exception: pass

    cpu = int(res.get("cpu-load", 0) or 0)
    total_mem = int(res.get("total-memory", 0) or 0)
    free_mem  = int(res.get("free-memory", 0) or 0)
    mem_pct = round((total_mem - free_mem) / total_mem * 100, 1) if total_mem else 0
    uptime = res.get("uptime", "")

    temps = {}
    for h in health:
        name = str(h.get("name", "")).lower()
        if "temp" in name:
            try:
                temps[name] = float(h.get("value", 0))
            except Exception:
                pass
    temp_max = max(temps.values()) if temps else None

    return {
        "online": True,
        "cpu": cpu,
        "mem_pct": mem_pct,
        "uptime": uptime,
        "sessions": sessions,
        "temp_max": temp_max,
        "version": res.get("version", ""),
        "board": res.get("board-name", ""),
    }


def probe_all_nas(get_db):
    """Lista todos os NAS com métricas. Em paralelo."""
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, nasname, shortname, description, mikrotik_user, mikrotik_pass, mikrotik_port
                  FROM nas
              ORDER BY shortname NULLS LAST, id
            """)
            nas_list = cur.fetchall()
    finally:
        conn.close()

    results = []
    has_creds = [n for n in nas_list if n.get("mikrotik_user") and n.get("mikrotik_pass")]

    metrics = {}
    if has_creds:
        with ThreadPoolExecutor(max_workers=min(8, len(has_creds))) as pool:
            futs = {pool.submit(probe_nas_metrics, n): n["id"] for n in has_creds}
            for fut in as_completed(futs, timeout=20):
                nas_id = futs[fut]
                try:
                    metrics[nas_id] = fut.result()
                except Exception as e:
                    metrics[nas_id] = {"online": False, "error": str(e)}

    for n in nas_list:
        item = {
            "id":          n["id"],
            "nasname":     n["nasname"],
            "shortname":   n.get("shortname") or n["nasname"],
            "description": n.get("description"),
            "has_api":     bool(n.get("mikrotik_user") and n.get("mikrotik_pass")),
        }
        item.update(metrics.get(n["id"], {"online": None}))
        results.append(item)
    return results
