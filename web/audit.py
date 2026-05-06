"""
Auditoria + alertas Telegram de eventos sensíveis.

Conjunto pequeno de helpers para registrar e alertar:
- log_audit()         — grava em audit_log
- audit_login_ok()    — login bem-sucedido
- audit_login_fail()  — login falhado + verifica brute-force
- audit_destrutivo()  — ações destrutivas (delete cliente, factory-reset, etc.)
- audit_api_key_ip()  — primeira vez que uma API key é vista de um IP

Convenções de severity:
- audit  → eventos rotineiros (login OK)
- warning → ações destrutivas, login falhado isolado
- critical → brute-force confirmado
"""
import logging
from datetime import datetime, timezone

log = logging.getLogger("audit")


def _client_ip(request):
    """Extrai IP do cliente respeitando X-Forwarded-For (atrás de proxy)."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "?"


def log_audit(get_db, *, usuario_id=None, usuario_nome=None, ip=None,
              action, target_type=None, target_id=None, detail=None):
    """Grava 1 linha em audit_log. Não falha o request se o write falhar."""
    import json
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_log
                    (ts, usuario_id, usuario_nome, ip, action,
                     target_type, target_id, detail)
                VALUES (NOW(), %s, %s, %s, %s, %s, %s, %s)
            """, (
                usuario_id, usuario_nome, ip, action,
                target_type,
                str(target_id) if target_id is not None else None,
                json.dumps(detail or {}, default=str),
            ))
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("audit_log insert failed: %s", e)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

def audit_login_ok(get_db, notifier, request, usuario):
    ip = _client_ip(request)
    log_audit(
        get_db,
        usuario_id=usuario["id"],
        usuario_nome=usuario["username"],
        ip=ip,
        action="login_ok",
        detail={"role": usuario.get("role")},
    )
    notifier.send(
        "login_ok",
        f"<b>🔐 Login no painel</b>\n"
        f"Usuário: <code>{usuario['username']}</code>\n"
        f"IP: <code>{ip}</code>",
        dedup_key=f"login_ok:{usuario['id']}:{ip}",
        severity="audit",
        cooldown=600,  # 10 min — não notifica reload de página
    )


def audit_login_fail(get_db, get_redis, notifier, request, username_tentado):
    ip = _client_ip(request)
    log_audit(
        get_db,
        usuario_nome=username_tentado,
        ip=ip,
        action="login_fail",
        detail={"username_tentado": username_tentado},
    )

    # Brute-force: conta falhas no Redis com TTL 60s
    try:
        r = get_redis()
        if r:
            limiar = _get_brute_limiar(get_db)
            key = f"audit:brute:{ip}"
            n = r.incr(key)
            if n == 1:
                r.expire(key, 60)
            if n >= limiar:
                notifier.send(
                    "brute_force",
                    f"<b>🚨 Tentativa de Brute-force</b>\n"
                    f"IP: <code>{ip}</code>\n"
                    f"{n} falhas em &lt; 60s\n"
                    f"Último username tentado: <code>{username_tentado}</code>",
                    dedup_key=f"brute_force:{ip}",
                    severity="critical",
                    cooldown=900,  # 15 min de cooldown por IP
                )
                log_audit(
                    get_db, ip=ip, action="brute_force_detected",
                    detail={"falhas": n, "limiar": limiar},
                )
                return
    except Exception as e:
        log.warning("brute-force counter error: %s", e)

    # Falha isolada — alerta single-shot, mas com cooldown maior pra não encher
    notifier.send(
        "login_fail",
        f"<b>⚠️ Login falhado</b>\n"
        f"Username: <code>{username_tentado}</code>\n"
        f"IP: <code>{ip}</code>",
        dedup_key=f"login_fail:{ip}",
        severity="warning",
        cooldown=1800,  # 30 min — login falhado isolado não merece spam
    )


def _get_brute_limiar(get_db):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT valor FROM alertas_config WHERE chave='alertas_brute_force_max'"
            )
            row = cur.fetchone()
        conn.close()
        return int(row[0]) if row else 3
    except Exception:
        return 3


# ---------------------------------------------------------------------------
# Ações destrutivas
# ---------------------------------------------------------------------------

DESTRUTIVE_LABELS = {
    "delete_cliente":       ("🗑️", "Cliente Excluído"),
    "delete_usuario":       ("🗑️", "Usuário do Painel Excluído"),
    "change_password":      ("🔑", "Senha de Usuário Alterada"),
    "cpe_factory_reset":    ("⚠️", "Factory Reset em CPE"),
    "cpe_reboot":           ("🔄", "Reboot de CPE"),
    "delete_nas":           ("🗑️", "NAS Excluído"),
    "delete_plano":         ("🗑️", "Plano Excluído"),
    "delete_pool":          ("🗑️", "Pool Excluído"),
    "radius_reapply_all":   ("⚠️", "Reaplicação Massiva RADIUS"),
    "coa_disconnect":       ("✂️", "Desconexão Forçada (CoA)"),
}


def audit_destrutivo(get_db, notifier, request, session, action,
                     target_type=None, target_id=None, detail=None):
    """Loga e alerta uma ação destrutiva no audit_log + Telegram."""
    ip = _client_ip(request)
    usuario_id = session.get("usuario_id")
    usuario_nome = session.get("usuario_username", "?")

    log_audit(
        get_db,
        usuario_id=usuario_id, usuario_nome=usuario_nome, ip=ip,
        action=action, target_type=target_type, target_id=target_id,
        detail=detail,
    )

    emoji, titulo = DESTRUTIVE_LABELS.get(action, ("⚠️", action))
    msg = (
        f"<b>{emoji} {titulo}</b>\n"
        f"Por: <code>{usuario_nome}</code> (IP {ip})"
    )
    if target_type and target_id is not None:
        msg += f"\nAlvo: {target_type} <code>{target_id}</code>"
    if detail:
        # Renderiza algumas chaves comuns de forma legível
        if isinstance(detail, dict):
            for k in ("nome", "cpf", "username", "ssid", "motivo"):
                if k in detail and detail[k]:
                    msg += f"\n{k}: <code>{detail[k]}</code>"

    notifier.send(
        action,
        msg,
        dedup_key=f"{action}:{target_id or 'na'}:{ip}",
        severity="warning",
        cooldown=60,  # ações destrutivas devem aparecer quase em tempo real
    )


# ---------------------------------------------------------------------------
# API Key — primeira vez vista de um IP
# ---------------------------------------------------------------------------

def audit_api_key_ip(get_db, notifier, request, api_key_id, api_key_nome=None):
    """
    Registra o IP em api_key_ips. Se for novo (primeira vez), dispara alerta.
    Retorna True se foi um IP novo.
    """
    ip = _client_ip(request)
    if not ip or ip == "?":
        return False

    novo_ip = False
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM api_key_ips WHERE api_key_id=%s AND ip=%s",
                (api_key_id, ip),
            )
            existe = cur.fetchone()
            if existe:
                cur.execute(
                    "UPDATE api_key_ips SET ultima_vez=NOW() "
                    "WHERE api_key_id=%s AND ip=%s",
                    (api_key_id, ip),
                )
            else:
                cur.execute(
                    "INSERT INTO api_key_ips (api_key_id, ip) VALUES (%s, %s) "
                    "ON CONFLICT DO NOTHING",
                    (api_key_id, ip),
                )
                novo_ip = True
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("api_key_ip track error: %s", e)
        return False

    if novo_ip:
        log_audit(
            get_db, ip=ip, action="api_key_new_ip",
            target_type="api_key", target_id=api_key_id,
            detail={"nome": api_key_nome},
        )
        notifier.send(
            "api_key_new_ip",
            f"<b>🔑 API Key usada de IP novo</b>\n"
            f"Key: <code>{api_key_nome or f'#{api_key_id}'}</code>\n"
            f"IP: <code>{ip}</code>",
            dedup_key=f"api_key_new_ip:{api_key_id}:{ip}",
            severity="warning",
            cooldown=86400,  # 24h por (key,ip)
        )
    return novo_ip
