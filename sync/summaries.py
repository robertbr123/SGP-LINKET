"""
Resumos diários enviados via Telegram.

Três tipos:
- Matinal (08:00 default)  — KPIs gerais para começar o dia
- Fim de turno (18:00)     — incidentes do dia, MTTR
- Heartbeat (09:00)        — apenas confirma que o bot está vivo

Para evitar duplo disparo no mesmo dia, cada resumo grava no Redis
"summary:<tipo>:last_date" com a data ISO. Antes de enviar, compara
com hoje — se igual, pula.
"""
import logging
import psycopg2.extras
from datetime import datetime, timezone, timedelta

log = logging.getLogger("summaries")


def _get_cfg(conn, chave, default=""):
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT valor FROM alertas_config WHERE chave=%s", (chave,))
            row = cur.fetchone()
            return row[0] if row else default
    except Exception:
        return default


def _parse_hhmm(s):
    """'08:00' → (8, 0). Retorna None se vazio/inválido."""
    if not s or ":" not in s:
        return None
    try:
        h, m = s.split(":", 1)
        return int(h), int(m)
    except Exception:
        return None


def _local_now():
    """Hora local do container (TZ pode ser UTC se não configurado)."""
    return datetime.now()


def _already_sent_today(redis_client, key):
    if not redis_client:
        return False
    try:
        last = redis_client.get(f"summary:{key}:last_date")
        return last == _local_now().strftime("%Y-%m-%d")
    except Exception:
        return False


def _mark_sent(redis_client, key):
    if not redis_client:
        return
    try:
        redis_client.set(
            f"summary:{key}:last_date",
            _local_now().strftime("%Y-%m-%d"),
            ex=2 * 86400,  # 2 dias — só pra não acumular para sempre
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Conteúdo dos resumos
# ---------------------------------------------------------------------------

def _morning_summary(conn):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT
                (SELECT COUNT(*) FROM clientes)                               AS total,
                (SELECT COUNT(*) FROM clientes WHERE status='ativo')          AS ativos,
                (SELECT COUNT(*) FROM clientes WHERE status='suspenso')       AS suspensos,
                (SELECT COUNT(*) FROM clientes WHERE status='pendente')       AS pendentes,
                (SELECT COUNT(*) FROM radacct  WHERE acctstoptime IS NULL)    AS online,
                (SELECT COUNT(*) FROM cpe_devices WHERE online = FALSE)       AS cpes_offline,
                (SELECT COUNT(*) FROM cpe_devices WHERE online = TRUE)        AS cpes_online,
                (SELECT COUNT(*) FROM chamados WHERE status='aberto')         AS chamados_abertos,
                (SELECT COUNT(*) FROM alert_state WHERE firing = TRUE)        AS alertas_firing
        """)
        kpis = cur.fetchone() or {}

        # Top 5 consumidores das últimas 24h
        cur.execute("""
            SELECT
                COALESCE(c.nome, ra.username) AS nome,
                ra.username,
                SUM(COALESCE(ra.acctinputoctets, 0) + COALESCE(ra.acctoutputoctets, 0))
                  / 1073741824.0 AS gb
            FROM radacct ra
            LEFT JOIN clientes c ON c.pppoe_login = ra.username
            WHERE COALESCE(ra.acctupdatetime, ra.acctstarttime) > NOW() - INTERVAL '24 hours'
            GROUP BY c.nome, ra.username
            HAVING SUM(COALESCE(ra.acctinputoctets, 0) + COALESCE(ra.acctoutputoctets, 0)) > 0
            ORDER BY gb DESC
            LIMIT 5
        """)
        top = cur.fetchall()

    linhas = [
        "<b>☀️ Resumo Matinal</b>",
        f"<i>{_local_now().strftime('%d/%m/%Y')}</i>",
        "",
        "<b>Clientes</b>",
        f"• Total: <b>{kpis.get('total', 0)}</b>",
        f"• Ativos: {kpis.get('ativos', 0)} · Suspensos: {kpis.get('suspensos', 0)} · Pendentes: {kpis.get('pendentes', 0)}",
        f"• Online agora: <b>{kpis.get('online', 0)}</b>",
        "",
        "<b>CPEs (TR-069)</b>",
        f"• Online: {kpis.get('cpes_online', 0)} · Offline: <b>{kpis.get('cpes_offline', 0)}</b>",
        "",
        "<b>Operação</b>",
        f"• Chamados abertos: <b>{kpis.get('chamados_abertos', 0)}</b>",
        f"• Alertas firing: <b>{kpis.get('alertas_firing', 0)}</b>",
    ]

    if top:
        linhas.append("")
        linhas.append("<b>Top 5 consumo (24h)</b>")
        for t in top:
            gb = float(t.get("gb") or 0)
            linhas.append(f"• <code>{t['username']}</code> — {gb:.1f} GB")

    return "\n".join(linhas)


def _shift_summary(conn):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT
                (SELECT COUNT(*) FROM chamados
                  WHERE criado_em::date = CURRENT_DATE)                    AS abertos_hoje,
                (SELECT COUNT(*) FROM chamados
                  WHERE status='resolvido'
                    AND resolvido_em::date = CURRENT_DATE)                 AS resolvidos_hoje,
                (SELECT COUNT(*) FROM chamados WHERE status='aberto')      AS pendentes,
                (SELECT EXTRACT(EPOCH FROM AVG(resolvido_em - criado_em))/60
                   FROM chamados
                  WHERE status='resolvido'
                    AND resolvido_em::date = CURRENT_DATE)                 AS mttr_min,
                (SELECT COUNT(*) FROM alert_state WHERE firing = TRUE)     AS alertas_firing,
                (SELECT COUNT(*) FROM alert_state
                  WHERE firing = FALSE
                    AND ultima_vez::date = CURRENT_DATE)                   AS alertas_resolvidos_hoje,
                (SELECT COUNT(*) FROM audit_log
                  WHERE ts::date = CURRENT_DATE
                    AND action IN ('login_fail','brute_force_detected'))   AS falhas_login_hoje
        """)
        kpis = cur.fetchone() or {}

        # Top 3 tipos de chamados abertos hoje
        cur.execute("""
            SELECT tipo, COUNT(*) AS qtd
              FROM chamados
             WHERE criado_em::date = CURRENT_DATE
          GROUP BY tipo
          ORDER BY qtd DESC
             LIMIT 3
        """)
        tipos = cur.fetchall()

        # Alertas ainda firing
        cur.execute("""
            SELECT dedup_key, severity FROM alert_state
             WHERE firing = TRUE
          ORDER BY severity DESC, last_sent_at DESC
             LIMIT 5
        """)
        firing = cur.fetchall()

    mttr = kpis.get("mttr_min")
    mttr_str = f"{float(mttr):.0f} min" if mttr else "—"

    linhas = [
        "<b>🌙 Resumo do Turno</b>",
        f"<i>{_local_now().strftime('%d/%m/%Y')}</i>",
        "",
        "<b>Chamados</b>",
        f"• Abertos hoje: {kpis.get('abertos_hoje', 0)}",
        f"• Resolvidos hoje: {kpis.get('resolvidos_hoje', 0)}",
        f"• Ainda pendentes: <b>{kpis.get('pendentes', 0)}</b>",
        f"• MTTR (resolução média hoje): <b>{mttr_str}</b>",
        "",
        "<b>Alertas</b>",
        f"• Firing agora: <b>{kpis.get('alertas_firing', 0)}</b>",
        f"• Resolvidos hoje: {kpis.get('alertas_resolvidos_hoje', 0)}",
        "",
        "<b>Segurança</b>",
        f"• Falhas de login hoje: {kpis.get('falhas_login_hoje', 0)}",
    ]

    if tipos:
        linhas.append("")
        linhas.append("<b>Tipos de chamado mais abertos</b>")
        for t in tipos:
            linhas.append(f"• {t['tipo']}: {t['qtd']}")

    if firing:
        linhas.append("")
        linhas.append("<b>Incidentes ainda abertos</b>")
        for f in firing:
            linhas.append(f"• [{f['severity']}] <code>{f['dedup_key']}</code>")

    return "\n".join(linhas)


def _heartbeat_message(conn, redis_client):
    last_cycle = "—"
    if redis_client:
        try:
            v = redis_client.get("sync:last_cycle_at")
            if v:
                # Formato ISO
                last_cycle = v.split("T")[1].split(".")[0] + " UTC"
        except Exception:
            pass

    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM alert_state WHERE firing = TRUE")
        firing = cur.fetchone()[0]

    return (
        f"<b>💚 Heartbeat — bot vivo</b>\n"
        f"<i>{_local_now().strftime('%d/%m %H:%M')}</i>\n"
        f"Último ciclo do sync: <code>{last_cycle}</code>\n"
        f"Alertas firing: <b>{firing}</b>"
    )


# ---------------------------------------------------------------------------
# Orquestrador (chamado a cada ciclo do sync)
# ---------------------------------------------------------------------------

# Análise IA opcional (só carrega se ANTHROPIC_API_KEY estiver setada)
try:
    from ai_summary import generate_morning_analysis, generate_shift_analysis
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    generate_morning_analysis = lambda c: None
    generate_shift_analysis = lambda c: None


JOBS = [
    # (chave_redis, chave_config, builder_fn, dedup_event, severity)
    ("morning",   "alertas_resumo_matinal_hora", _morning_summary,   "summary_morning",   "info"),
    ("shift",     "alertas_resumo_turno_hora",   _shift_summary,     "summary_shift",     "info"),
    ("heartbeat", "alertas_heartbeat_hora",      None,               "summary_heartbeat", "info"),
]

# Predição de falhas em CPE roda junto com o matinal (1x/dia)
try:
    from predictions import check_cpe_predictions, cleanup_old_rx_history
    PREDICTIONS_AVAILABLE = True
except ImportError:
    PREDICTIONS_AVAILABLE = False


def maybe_send_summaries(conn, redis_client, notifier):
    """
    Verifica cada um dos 3 resumos:
    - lê o horário configurado (HH:MM)
    - se a hora atual está entre alvo e alvo+1h E não foi enviado hoje, envia
    """
    now = _local_now()

    for chave, cfg_key, builder, event, severity in JOBS:
        hora_str = _get_cfg(conn, cfg_key, "")
        if not hora_str:
            continue  # desativado

        hhmm = _parse_hhmm(hora_str)
        if hhmm is None:
            continue

        target = now.replace(hour=hhmm[0], minute=hhmm[1], second=0, microsecond=0)
        # Janela de 1h após o horário-alvo (cobre atrasos do sync)
        if not (target <= now < target + timedelta(hours=1)):
            continue

        if _already_sent_today(redis_client, chave):
            continue

        try:
            if chave == "heartbeat":
                msg = _heartbeat_message(conn, redis_client)
            elif chave == "morning":
                msg = builder(conn)
                # Anexa análise IA + roda predições no mesmo slot diário
                if PREDICTIONS_AVAILABLE:
                    try:
                        check_cpe_predictions(conn, redis_client, notifier)
                        cleanup_old_rx_history(conn, days=30)
                    except Exception as e:
                        log.warning("predictions error: %s", e)
                ai_text = generate_morning_analysis(conn) if AI_AVAILABLE else None
                if ai_text: msg += ai_text
            elif chave == "shift":
                msg = builder(conn)
                ai_text = generate_shift_analysis(conn) if AI_AVAILABLE else None
                if ai_text: msg += ai_text
            else:
                msg = builder(conn)
        except Exception as e:
            log.warning("summary build error (%s): %s", chave, e)
            continue

        # force=True para garantir disparo mesmo durante manutenção (resumos não devem sumir)
        ok = notifier.send(event, msg, severity=severity, cooldown=0, force=False)
        if ok:
            _mark_sent(redis_client, chave)
            log.info("Resumo '%s' enviado", chave)
