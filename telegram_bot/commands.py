"""
Comandos do bot Telegram.

Cada handler recebe (chat_id, args, ctx) onde ctx tem:
  - token, get_db, get_redis, notifier, sender (string label)

Comandos disponíveis:
  /help                — lista comandos
  /status              — KPIs em tempo real
  /cliente <CPF|login> — busca cliente
  /online              — top 20 sessões ativas
  /desconectar <login> — força CoA disconnect
  /reiniciar_cpe <id>  — reboot via GenieACS
  /silenciar <Xm|Xh>   — pausa alertas
"""
import os
import re
import json
import time
import logging
import subprocess
from datetime import datetime, timezone

import requests
import psycopg2.extras
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import librouteros
    MIKROTIK_AVAILABLE = True
except ImportError:
    MIKROTIK_AVAILABLE = False

log = logging.getLogger("bot.commands")

GENIEACS_NBI_URL = os.environ.get("GENIEACS_NBI_URL", "http://genieacs-nbi:7557").rstrip("/")


# ---------------------------------------------------------------------------
# Telegram helpers
# ---------------------------------------------------------------------------

def send_message(token, chat_id, text):
    """Envia mensagem (sempre HTML)."""
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=8,
        )
        return r.ok
    except Exception as e:
        log.warning("sendMessage error: %s", e)
        return False


def _audit(get_db, sender, action, target_type=None, target_id=None, detail=None):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_log
                    (ts, usuario_nome, ip, action, target_type, target_id, detail)
                VALUES (NOW(), %s, %s, %s, %s, %s, %s)
            """, (
                f"telegram:{sender}",
                "telegram-bot",
                action,
                target_type,
                str(target_id) if target_id is not None else None,
                json.dumps(detail or {}, default=str),
            ))
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("audit insert error: %s", e)


def _fmt_bytes(b):
    b = b or 0
    if b >= 1_073_741_824: return f"{b/1_073_741_824:.2f} GB"
    if b >= 1_048_576:     return f"{b/1_048_576:.2f} MB"
    if b >= 1024:          return f"{b/1024:.2f} KB"
    return f"{b} B"


# ---------------------------------------------------------------------------
# /help
# ---------------------------------------------------------------------------

HELP_TEXT = (
    "<b>🤖 Bot SGP-LINKET — comandos</b>\n\n"
    "/status — KPIs em tempo real\n"
    "/cliente <code>&lt;CPF ou login&gt;</code> — busca cliente\n"
    "/online — top 20 sessões PPPoE ativas\n"
    "/desconectar <code>&lt;login&gt;</code> — força CoA disconnect\n"
    "/reiniciar_cpe <code>&lt;id&gt;</code> — reboot do CPE via TR-069\n"
    "/silenciar <code>&lt;30m|2h|1h30m&gt;</code> — pausa alertas\n"
    "/help — esta ajuda"
)


def cmd_help(chat_id, args, ctx):
    send_message(ctx["token"], chat_id, HELP_TEXT)


# ---------------------------------------------------------------------------
# /status — KPIs em tempo real
# ---------------------------------------------------------------------------

def cmd_status(chat_id, args, ctx):
    conn = ctx["get_db"]()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT
                  (SELECT COUNT(*) FROM clientes)                            AS total,
                  (SELECT COUNT(*) FROM clientes WHERE status='ativo')       AS ativos,
                  (SELECT COUNT(*) FROM clientes WHERE status='suspenso')    AS suspensos,
                  (SELECT COUNT(*) FROM radacct WHERE acctstoptime IS NULL)  AS online_radacct,
                  (SELECT COUNT(*) FROM cpe_devices WHERE online=FALSE)      AS cpes_off,
                  (SELECT COUNT(*) FROM chamados WHERE status='aberto')      AS chamados,
                  (SELECT COUNT(*) FROM alert_state WHERE firing=TRUE)       AS firing
            """)
            k = cur.fetchone()
    finally:
        conn.close()

    # Online real vem do MikroTik (radacct pode estar defasado)
    sessoes_mt = _online_via_mikrotik(ctx["get_db"])
    if sessoes_mt is not None:
        online = len(sessoes_mt)
        fonte = "MikroTik"
    else:
        online = k["online_radacct"]
        fonte = "radacct"

    txt = (
        f"<b>📊 Status — {datetime.now().strftime('%d/%m %H:%M')}</b>\n\n"
        f"<b>Clientes</b>: {k['total']} (ativos: {k['ativos']} · suspensos: {k['suspensos']})\n"
        f"<b>Online agora</b>: {online} <i>({fonte})</i>\n"
        f"<b>CPEs offline</b>: {k['cpes_off']}\n"
        f"<b>Chamados abertos</b>: {k['chamados']}\n"
        f"<b>Alertas firing</b>: {k['firing']}"
    )
    send_message(ctx["token"], chat_id, txt)


# ---------------------------------------------------------------------------
# /cliente <CPF ou login>
# ---------------------------------------------------------------------------

def cmd_cliente(chat_id, args, ctx):
    chave = (args or "").strip()
    if not chave:
        send_message(ctx["token"], chat_id, "Uso: <code>/cliente CPF</code> ou <code>/cliente login_pppoe</code>")
        return

    cpf_limpo = re.sub(r"\D", "", chave)

    conn = ctx["get_db"]()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT c.*, p.nome AS plano_nome
                  FROM clientes c
                  LEFT JOIN planos p ON p.id = c.plano_id
                 WHERE c.cpf = %s OR c.pppoe_login ILIKE %s OR c.cpf = %s
                 LIMIT 1
            """, (cpf_limpo, chave, chave))
            cli = cur.fetchone()

            if not cli:
                send_message(ctx["token"], chat_id, f"❌ Cliente não encontrado: <code>{chave}</code>")
                return

            cur.execute("""
                SELECT acctstarttime, framedipaddress::text AS ip, nasipaddress::text AS nas,
                       acctinputoctets, acctoutputoctets
                  FROM radacct
                 WHERE username = %s AND acctstoptime IS NULL
              ORDER BY acctstarttime DESC LIMIT 1
            """, (cli["pppoe_login"],))
            sessao = cur.fetchone()

            cur.execute("""
                SELECT modelo, fabricante, online, rx_power, ip_wan
                  FROM cpe_devices
                 WHERE cliente_id = %s LIMIT 1
            """, (cli["id"],))
            cpe = cur.fetchone()
    finally:
        conn.close()

    online = "🟢 online" if sessao else "🔴 offline"
    linhas = [
        f"<b>👤 Cliente #{cli['id']}</b>",
        f"<b>{cli['nome']}</b>",
        f"CPF: <code>{cli['cpf']}</code>",
        f"PPPoE: <code>{cli['pppoe_login'] or '—'}</code>",
        f"Status: <b>{cli['status']}</b> · {online}",
        f"Plano: {cli.get('plano_nome') or cli.get('plano') or '—'} "
        f"({cli['velocidade_down']}↓/{cli['velocidade_up']}↑ Mbps)",
    ]

    if sessao:
        traffic = (sessao.get("acctinputoctets") or 0) + (sessao.get("acctoutputoctets") or 0)
        linhas.append("")
        linhas.append("<b>Sessão atual</b>")
        linhas.append(f"IP: <code>{sessao['ip']}</code>")
        linhas.append(f"NAS: <code>{sessao['nas']}</code>")
        linhas.append(f"Início: {sessao['acctstarttime'].strftime('%d/%m %H:%M') if sessao['acctstarttime'] else '—'}")
        linhas.append(f"Tráfego: {_fmt_bytes(traffic)}")

    if cpe:
        linhas.append("")
        linhas.append("<b>CPE</b>")
        cpe_status = "🟢" if cpe["online"] else "🔴"
        linhas.append(f"{cpe_status} {cpe.get('fabricante') or ''} {cpe.get('modelo') or ''}".strip())
        if cpe.get("ip_wan"):
            linhas.append(f"IP WAN: <code>{cpe['ip_wan']}</code>")
        if cpe.get("rx_power") is not None:
            linhas.append(f"Rx Power: {cpe['rx_power']:.1f} dBm")

    send_message(ctx["token"], chat_id, "\n".join(linhas))


# ---------------------------------------------------------------------------
# /online — top 20 sessões (MikroTik API primário, radacct fallback)
# ---------------------------------------------------------------------------

def _probe_nas_active(nas):
    """Retorna lista de sessões PPPoE ativas no NAS via API MikroTik."""
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
                "username": s.get("name", ""),
                "ip":       s.get("address", ""),
                "uptime":   s.get("uptime", ""),
                "service":  s.get("service", ""),
                "caller":   s.get("caller-id", ""),
                "nas_label": nas.get("shortname") or nas["nasname"],
            })
    finally:
        try: api.close()
        except Exception: pass
    return sessoes


def _online_via_mikrotik(get_db):
    """Coleta sessões ativas de TODOS os NAS com credenciais. Paralelo."""
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


def _enrich_with_clients(sessoes, get_db):
    """Cruza com clientes pra adicionar nome."""
    if not sessoes:
        return sessoes
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT pppoe_login, nome FROM clientes WHERE pppoe_login IS NOT NULL")
            mapa = {r["pppoe_login"]: r["nome"] for r in cur.fetchall()}
    finally:
        conn.close()
    for s in sessoes:
        s["cliente_nome"] = mapa.get(s["username"], "")
    return sessoes


def _online_via_radacct(get_db):
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT ra.username,
                       ra.framedipaddress::text AS ip,
                       ra.nasipaddress::text AS nas_label,
                       ra.acctstarttime,
                       (COALESCE(ra.acctinputoctets,0) + COALESCE(ra.acctoutputoctets,0)) AS traffic,
                       c.nome AS cliente_nome
                  FROM radacct ra
                  LEFT JOIN clientes c ON c.pppoe_login = ra.username
                 WHERE ra.acctstoptime IS NULL
              ORDER BY traffic DESC
            """)
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def cmd_online(chat_id, args, ctx):
    sessoes = _online_via_mikrotik(ctx["get_db"])
    fonte = "MikroTik API"
    if not sessoes:
        sessoes = _online_via_radacct(ctx["get_db"])
        fonte = "radacct (FreeRADIUS)"

    if not sessoes:
        send_message(ctx["token"], chat_id,
                     "<i>Nenhuma sessão PPPoE ativa em nenhum NAS.</i>")
        return

    sessoes = _enrich_with_clients(sessoes, ctx["get_db"])
    total = len(sessoes)

    # Ordena: se veio do radacct, por traffic; se veio do MikroTik, por uptime (mais antigos primeiro)
    if "traffic" in sessoes[0]:
        sessoes.sort(key=lambda s: s.get("traffic") or 0, reverse=True)
    top = sessoes[:20]

    linhas = [
        f"<b>🟢 {total} sessão(ões) PPPoE ativa(s)</b>",
        f"<i>Fonte: {fonte} · top {len(top)} mostrada(s)</i>",
        "",
    ]
    for s in top:
        nome = (s.get("cliente_nome") or "?")[:30]
        if s.get("traffic") is not None:  # radacct
            linhas.append(
                f"<code>{s['username']}</code> ({nome})\n"
                f"  IP {s.get('ip','—')} · {_fmt_bytes(s['traffic'])}"
            )
        else:  # MikroTik
            uptime = s.get("uptime", "")
            extra = f" · {uptime}" if uptime else ""
            linhas.append(
                f"<code>{s['username']}</code> ({nome})\n"
                f"  IP {s.get('ip','—')} · NAS {s['nas_label']}{extra}"
            )
    send_message(ctx["token"], chat_id, "\n".join(linhas))


# ---------------------------------------------------------------------------
# /desconectar <login>
# ---------------------------------------------------------------------------

def cmd_desconectar(chat_id, args, ctx):
    login = (args or "").strip()
    if not login:
        send_message(ctx["token"], chat_id, "Uso: <code>/desconectar &lt;login_pppoe&gt;</code>")
        return

    conn = ctx["get_db"]()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT nasipaddress::text AS nas_ip
                  FROM radacct
                 WHERE username = %s AND acctstoptime IS NULL
              ORDER BY acctstarttime DESC LIMIT 1
            """, (login,))
            sessao = cur.fetchone()
            if not sessao:
                send_message(ctx["token"], chat_id,
                             f"⚠️ <code>{login}</code> não tem sessão ativa.")
                return

            nas_ip = sessao["nas_ip"]
            cur.execute("SELECT secret FROM nas WHERE nasname = %s", (nas_ip,))
            nas_row = cur.fetchone()
            secret = nas_row["secret"] if nas_row else "testing123"
    finally:
        conn.close()

    _audit(ctx["get_db"], ctx["sender"], "bot_command:desconectar",
           target_type="cliente_pppoe", target_id=login,
           detail={"nas_ip": nas_ip})

    try:
        proc = subprocess.run(
            ["radclient", "-x", f"{nas_ip}:3799", "disconnect", secret],
            input=f'User-Name="{login}"',
            capture_output=True, text=True, timeout=10,
        )
        ok = proc.returncode == 0
    except FileNotFoundError:
        send_message(ctx["token"], chat_id,
                     "❌ <code>radclient</code> não está instalado no container.")
        return
    except Exception as e:
        send_message(ctx["token"], chat_id, f"❌ Erro: <code>{e}</code>")
        return

    if ok:
        send_message(ctx["token"], chat_id,
                     f"✂️ <b>Desconectado</b>\nLogin: <code>{login}</code>\nNAS: <code>{nas_ip}</code>")
    else:
        send_message(ctx["token"], chat_id,
                     f"⚠️ CoA enviado mas NAS retornou erro.\n<pre>{proc.stderr[:300]}</pre>")


# ---------------------------------------------------------------------------
# /reiniciar_cpe <id>
# ---------------------------------------------------------------------------

def cmd_reiniciar_cpe(chat_id, args, ctx):
    arg = (args or "").strip()
    if not arg.isdigit():
        send_message(ctx["token"], chat_id, "Uso: <code>/reiniciar_cpe &lt;id&gt;</code> (id numérico do CPE)")
        return
    cpe_id = int(arg)

    conn = ctx["get_db"]()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT cpe.genieacs_id, cpe.modelo, cpe.serial_number, c.nome
                  FROM cpe_devices cpe
                  LEFT JOIN clientes c ON c.id = cpe.cliente_id
                 WHERE cpe.id = %s
            """, (cpe_id,))
            cpe = cur.fetchone()
    finally:
        conn.close()

    if not cpe or not cpe.get("genieacs_id"):
        send_message(ctx["token"], chat_id, f"❌ CPE id={cpe_id} não encontrado ou sem genieacs_id.")
        return

    _audit(ctx["get_db"], ctx["sender"], "bot_command:reiniciar_cpe",
           target_type="cpe", target_id=cpe_id,
           detail={"modelo": cpe.get("modelo"), "serial": cpe.get("serial_number")})

    import urllib.parse as up
    encoded = up.quote(cpe["genieacs_id"], safe="")
    try:
        r = requests.post(
            f"{GENIEACS_NBI_URL}/devices/{encoded}/tasks?timeout=3000&connection_request",
            json={"name": "reboot"},
            timeout=12,
        )
        if r.ok:
            send_message(ctx["token"], chat_id,
                         f"🔄 <b>Reboot enviado ao CPE</b>\n"
                         f"ID: {cpe_id}\n"
                         f"Cliente: {cpe.get('nome') or '?'}\n"
                         f"Modelo: {cpe.get('modelo') or '?'}")
        else:
            send_message(ctx["token"], chat_id,
                         f"⚠️ GenieACS retornou {r.status_code}\n<pre>{r.text[:300]}</pre>")
    except Exception as e:
        send_message(ctx["token"], chat_id, f"❌ Erro: <code>{e}</code>")


# ---------------------------------------------------------------------------
# /silenciar <duração>
# ---------------------------------------------------------------------------

DURATION_RE = re.compile(r"(\d+)\s*([hm])", re.IGNORECASE)


def _parse_duration(s):
    """Converte '30m', '2h', '1h30m' para minutos. Retorna None se inválido."""
    s = s.strip().lower()
    if not s:
        return None
    total = 0
    matches = DURATION_RE.findall(s)
    if not matches:
        # talvez só um número, assume minutos
        if s.isdigit():
            return int(s)
        return None
    for n, unit in matches:
        n = int(n)
        if unit == "h":
            total += n * 60
        else:
            total += n
    return total or None


def cmd_silenciar(chat_id, args, ctx):
    parts = (args or "").strip().split(maxsplit=1)
    if not parts:
        send_message(ctx["token"], chat_id,
                     "Uso: <code>/silenciar 30m</code>, <code>/silenciar 1h</code>, <code>/silenciar 2h motivo aqui</code>")
        return

    minutos = _parse_duration(parts[0])
    if not minutos or minutos < 1 or minutos > 7 * 24 * 60:
        send_message(ctx["token"], chat_id,
                     "❌ Duração inválida. Exemplo: <code>30m</code>, <code>2h</code>, <code>1h30m</code>")
        return

    motivo = parts[1] if len(parts) > 1 else None

    conn = ctx["get_db"]()
    try:
        new_id = ctx["notifier"].silence(
            conn, minutos=minutos, escopo="all", motivo=motivo,
            criado_por=f"telegram:{ctx['sender']}",
        )
    finally:
        conn.close()

    _audit(ctx["get_db"], ctx["sender"], "bot_command:silenciar",
           target_type="maintenance", target_id=new_id,
           detail={"minutos": minutos, "motivo": motivo})

    h, m = divmod(minutos, 60)
    dur_str = f"{h}h{m:02d}m" if h else f"{m}m"
    motivo_str = f"\nMotivo: <i>{motivo}</i>" if motivo else ""
    send_message(ctx["token"], chat_id,
                 f"🔕 <b>Alertas silenciados por {dur_str}</b>"
                 f"{motivo_str}\n"
                 f"<i>Janela #{new_id} ativa. Use <code>/help</code> para mais.</i>")


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

HANDLERS = {
    "help":          cmd_help,
    "start":         cmd_help,
    "status":        cmd_status,
    "cliente":       cmd_cliente,
    "online":        cmd_online,
    "desconectar":   cmd_desconectar,
    "reiniciar_cpe": cmd_reiniciar_cpe,
    "silenciar":     cmd_silenciar,
}


def dispatch(text, chat_id, sender, token, get_db, get_redis, notifier):
    raw = text.strip()
    cmd, _, args = raw.partition(" ")
    cmd = cmd.lstrip("/").split("@")[0].lower()  # /status@MeuBot → status

    handler = HANDLERS.get(cmd)
    if not handler:
        send_message(
            token, chat_id,
            f"❓ Comando <code>/{cmd}</code> desconhecido. Use /help."
        )
        return

    ctx = {
        "token":     token,
        "get_db":    get_db,
        "get_redis": get_redis,
        "notifier":  notifier,
        "sender":    sender,
    }
    handler(chat_id, args, ctx)
