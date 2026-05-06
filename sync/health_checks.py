"""
Verificações de infraestrutura → alertas Telegram via notifier.

Convenções de dedup_key:
  nas_down:<id>           — MikroTik não responde API
  nas_cpu:<id>            — CPU acima do limiar
  nas_mem:<id>            — memória acima do limiar
  nas_temp:<id>           — temperatura acima do limiar
  nas_iface:<id>:<iface>  — interface caiu (running=false)
  service_down:postgres   — banco inacessível
  service_down:redis      — redis inacessível
  service_down:genieacs   — GenieACS inacessível
  service_down:sgp_api    — endpoint SGP retornando erro
  service_down:freeradius — sem auths recentes apesar de clientes online
  sync_lag                — ciclo do sync demorando mais que limiar

Estado de "2 ciclos consecutivos" é guardado em Redis com keys:
  health:fail_count:<dedup_key> = N (TTL 1h)
"""
import os
import time
import logging
import requests
import psycopg2
import psycopg2.extras
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import librouteros
    MIKROTIK_AVAILABLE = True
except ImportError:
    MIKROTIK_AVAILABLE = False

log = logging.getLogger("health")

GENIEACS_NBI_URL = os.environ.get("GENIEACS_NBI_URL", "http://genieacs-nbi:7557").rstrip("/")
SGP_URL = os.environ.get("SGP_URL", "https://linknetam.sgp.net.br/api/ura/consultacliente/")
SGP_TOKEN = os.environ.get("SGP_TOKEN", "")
SGP_APP = os.environ.get("SGP_APP", "APP")

# Após quantas falhas consecutivas o alerta sobe (evita falsos-positivos por jitter)
FAIL_THRESHOLD = 2

# Timeout pra cada conexão MikroTik
MT_TIMEOUT = 6

# Ciclo de health check (chamado dentro do loop principal do sync)
# A cada ciclo do sync, contamos como uma "tentativa" — então 2 ciclos = ~10 min com SYNC_INTERVAL=300
# Para detectar mais rápido, ajuste SYNC_INTERVAL ou rode estes checks num loop separado.

# ---------------------------------------------------------------------------
# Helpers de contagem (Redis)
# ---------------------------------------------------------------------------

def _get_cfg(conn, chave, default=""):
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT valor FROM alertas_config WHERE chave=%s", (chave,))
            row = cur.fetchone()
            return row[0] if row else default
    except Exception:
        return default


def _bump_fail(redis_client, key):
    """Incrementa contador de falha. Retorna o novo valor."""
    if not redis_client:
        return FAIL_THRESHOLD  # sem Redis, alerta no primeiro ciclo
    try:
        full = f"health:fail_count:{key}"
        n = redis_client.incr(full)
        if n == 1:
            redis_client.expire(full, 3600)  # TTL 1h
        return n
    except Exception:
        return FAIL_THRESHOLD


def _reset_fail(redis_client, key):
    if not redis_client:
        return
    try:
        redis_client.delete(f"health:fail_count:{key}")
    except Exception:
        pass


def _eval_check(notifier, redis_client, ok, dedup_key, fire_msg, resolve_msg,
                severity="critical", threshold=FAIL_THRESHOLD):
    """
    Padrão genérico:
    - ok=False: incrementa fail_count, dispara fire quando >= threshold
    - ok=True: zera fail_count, dispara resolve se estava firing
    """
    if ok:
        _reset_fail(redis_client, dedup_key)
        notifier.resolve(dedup_key, msg=resolve_msg)
    else:
        n = _bump_fail(redis_client, dedup_key)
        if n >= threshold:
            notifier.fire(dedup_key, fire_msg, severity=severity, cooldown=900)


# ---------------------------------------------------------------------------
# 1) NAS / MikroTik (down + CPU + mem + temp + interfaces)
# ---------------------------------------------------------------------------

def _probe_one_nas(nas):
    """
    Conecta no MikroTik e coleta resource + interfaces + health.
    Retorna dict {ok, cpu, mem_pct, temps, ifaces} ou {ok: False}.
    """
    if not MIKROTIK_AVAILABLE:
        return {"ok": False, "error": "librouteros indisponível"}

    try:
        api = librouteros.connect(
            host=nas["nasname"],
            username=nas["mikrotik_user"],
            password=nas["mikrotik_pass"],
            port=int(nas.get("mikrotik_port") or 8728),
            timeout=MT_TIMEOUT,
        )
    except Exception as e:
        return {"ok": False, "error": str(e)}

    try:
        try:
            resource = list(api("/system/resource/print"))[0]
        except Exception:
            resource = {}

        try:
            ifaces = list(api("/interface/print"))
        except Exception:
            ifaces = []

        try:
            health = list(api("/system/health/print"))
        except Exception:
            health = []

        cpu = int(resource.get("cpu-load", 0) or 0)
        total_mem = int(resource.get("total-memory", 0) or 0)
        free_mem  = int(resource.get("free-memory", 0) or 0)
        mem_pct   = round((total_mem - free_mem) / total_mem * 100, 1) if total_mem else 0

        temps = {}
        for h in health:
            name = str(h.get("name", "")).lower()
            if "temp" in name:
                try:
                    temps[name] = float(h.get("value", 0))
                except Exception:
                    pass

        return {
            "ok": True,
            "cpu": cpu,
            "mem_pct": mem_pct,
            "temps": temps,
            "ifaces": ifaces,
        }
    finally:
        try: api.close()
        except Exception: pass


def check_nas_health(conn, redis_client, notifier):
    cpu_max  = float(_get_cfg(conn, "alertas_nas_cpu_pct",  "85"))
    mem_max  = float(_get_cfg(conn, "alertas_nas_mem_pct",  "85"))
    temp_max = float(_get_cfg(conn, "alertas_nas_temp_c",   "70"))

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT id, nasname, shortname, mikrotik_user, mikrotik_pass, mikrotik_port
              FROM nas
             WHERE mikrotik_user IS NOT NULL AND mikrotik_pass IS NOT NULL
               AND mikrotik_pass != ''
        """)
        nas_list = cur.fetchall()

    if not nas_list:
        return

    # Probe paralelo (até 8 NAS de cada vez)
    results = {}
    with ThreadPoolExecutor(max_workers=min(8, len(nas_list))) as pool:
        futures = {pool.submit(_probe_one_nas, n): n for n in nas_list}
        for fut in as_completed(futures, timeout=MT_TIMEOUT * 2 + 5):
            n = futures[fut]
            try:
                results[n["id"]] = fut.result()
            except Exception as e:
                results[n["id"]] = {"ok": False, "error": str(e)}

    for nas in nas_list:
        nas_id = nas["id"]
        label = nas.get("shortname") or nas["nasname"]
        res = results.get(nas_id, {"ok": False, "error": "timeout"})

        # 1.1) NAS down
        _eval_check(
            notifier, redis_client,
            ok=res.get("ok", False),
            dedup_key=f"nas_down:{nas_id}",
            fire_msg=(
                f"<b>🔴 NAS Inacessível</b>\n"
                f"<b>{label}</b> ({nas['nasname']})\n"
                f"Erro: <code>{res.get('error','?')}</code>"
            ),
            resolve_msg=f"<b>✅ NAS voltou:</b> {label} ({nas['nasname']})",
            severity="critical",
        )

        if not res.get("ok"):
            continue  # não checa métricas de NAS down

        # 1.2) CPU alto
        cpu = res["cpu"]
        _eval_check(
            notifier, redis_client,
            ok=cpu < cpu_max,
            dedup_key=f"nas_cpu:{nas_id}",
            fire_msg=f"<b>⚠️ CPU Alta</b>\n<b>{label}</b>: {cpu}% (limiar {cpu_max:.0f}%)",
            resolve_msg=f"<b>✅ CPU normalizou</b>\n<b>{label}</b>: {cpu}%",
            severity="warning",
        )

        # 1.3) Memória alta
        mem = res["mem_pct"]
        _eval_check(
            notifier, redis_client,
            ok=mem < mem_max,
            dedup_key=f"nas_mem:{nas_id}",
            fire_msg=f"<b>⚠️ Memória Alta</b>\n<b>{label}</b>: {mem}% (limiar {mem_max:.0f}%)",
            resolve_msg=f"<b>✅ Memória normalizou</b>\n<b>{label}</b>: {mem}%",
            severity="warning",
        )

        # 1.4) Temperatura alta (qualquer sensor)
        for sensor, val in res["temps"].items():
            sensor_clean = sensor.replace("temperature", "").strip("- ")
            _eval_check(
                notifier, redis_client,
                ok=val < temp_max,
                dedup_key=f"nas_temp:{nas_id}:{sensor_clean}",
                fire_msg=(
                    f"<b>🌡️ Temperatura Alta</b>\n"
                    f"<b>{label}</b> [{sensor_clean}]: {val:.1f}°C (limiar {temp_max:.0f}°C)"
                ),
                resolve_msg=f"<b>✅ Temperatura ok</b>\n<b>{label}</b> [{sensor_clean}]: {val:.1f}°C",
                severity="warning",
            )

        # 1.5) Interfaces físicas caídas
        # Critério: só alerta interface que JÁ esteve up alguma vez (Redis,
        # TTL 30 dias). Porta sem cabo nunca esteve up = não alerta.
        # Combinado com _eval_check(threshold=2), evita falso-positivo de
        # uplink que oscila brevemente.
        for iface in res["ifaces"]:
            iname = str(iface.get("name", ""))
            if not iname:
                continue
            disabled = str(iface.get("disabled", "")).lower() in ("true", "yes", "1")
            if disabled:
                continue
            itype = str(iface.get("type", "") or "")
            # Apenas interfaces físicas reais (ignora VLAN/bridge/wlan etc.)
            if itype not in ("ether", "sfp", "sfp-sfpplus"):
                continue

            running = str(iface.get("running", "")).lower() in ("true", "yes", "1")
            rx_byte = int(iface.get("rx-byte", 0) or 0)
            tx_byte = int(iface.get("tx-byte", 0) or 0)
            has_traffic = (rx_byte + tx_byte) > 0
            redis_key = f"iface_was_up:{nas_id}:{iname}"

            # Marca a porta como "já esteve em uso" quando vê running=true
            # OU quando há tráfego acumulado significativo (>1MB)
            esteve_up = False
            if redis_client:
                try:
                    if running or (rx_byte + tx_byte) > 1_000_000:
                        redis_client.set(redis_key, "1", ex=30 * 86400)
                        esteve_up = True
                    else:
                        esteve_up = bool(redis_client.get(redis_key))
                except Exception:
                    esteve_up = has_traffic
            else:
                # Sem Redis, fallback: usa tráfego como prova de uso
                esteve_up = has_traffic

            # Não alerta porta que nunca esteve em uso (cabo desconectado)
            if not esteve_up:
                continue

            _eval_check(
                notifier, redis_client,
                ok=running,
                dedup_key=f"nas_iface:{nas_id}:{iname}",
                fire_msg=(
                    f"<b>🔌 Interface Caiu</b>\n"
                    f"<b>{label}</b> → <code>{iname}</code> ({itype})"
                ),
                resolve_msg=f"<b>✅ Interface UP</b>\n<b>{label}</b> → <code>{iname}</code>",
                severity="critical",
            )


# ---------------------------------------------------------------------------
# 2) Serviços externos (Postgres, Redis, GenieACS, SGP API)
# ---------------------------------------------------------------------------

def check_external_services(conn, redis_client, notifier):
    # 2.1) Postgres — se chegamos aqui, conn está OK. Mas validamos com SELECT 1.
    pg_ok = True
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
    except Exception as e:
        pg_ok = False
        log.warning("postgres check failed: %s", e)
    _eval_check(
        notifier, redis_client, pg_ok,
        dedup_key="service_down:postgres",
        fire_msg="<b>🔴 PostgreSQL inacessível</b>",
        resolve_msg="<b>✅ PostgreSQL voltou</b>",
        severity="critical",
    )

    # 2.2) Redis
    redis_ok = False
    try:
        if redis_client:
            redis_ok = bool(redis_client.ping())
    except Exception as e:
        log.warning("redis check failed: %s", e)
    _eval_check(
        notifier, redis_client, redis_ok,
        dedup_key="service_down:redis",
        fire_msg="<b>🔴 Redis inacessível</b>",
        resolve_msg="<b>✅ Redis voltou</b>",
        severity="critical",
    )

    # 2.3) GenieACS NBI
    genie_ok = False
    try:
        r = requests.get(f"{GENIEACS_NBI_URL}/devices?limit=1", timeout=5)
        genie_ok = r.ok
    except Exception as e:
        log.warning("genieacs check failed: %s", e)
    _eval_check(
        notifier, redis_client, genie_ok,
        dedup_key="service_down:genieacs",
        fire_msg="<b>🔴 GenieACS inacessível</b>",
        resolve_msg="<b>✅ GenieACS voltou</b>",
        severity="warning",
    )

    # 2.4) SGP API
    sgp_ok = False
    try:
        if SGP_TOKEN:
            r = requests.post(
                SGP_URL,
                data={"token": SGP_TOKEN, "app": SGP_APP, "cpfcnpj": "00000000000"},
                timeout=10,
            )
            # 200 mesmo com CPF inválido é OK — só queremos saber se o servidor responde
            sgp_ok = r.status_code in (200, 400, 422)
    except Exception as e:
        log.warning("sgp check failed: %s", e)
    _eval_check(
        notifier, redis_client, sgp_ok,
        dedup_key="service_down:sgp_api",
        fire_msg="<b>🔴 SGP API com erro</b>\nClientes novos podem ficar em status 'pendente'.",
        resolve_msg="<b>✅ SGP API voltou</b>",
        severity="critical",
    )


# ---------------------------------------------------------------------------
# 3) FreeRADIUS — heurística: tem auth ou accounting nos últimos N min?
# ---------------------------------------------------------------------------

def check_freeradius(conn, redis_client, notifier):
    """
    Se há sessões PPPoE ativas no MikroTik mas radacct/radpostauth não recebeu
    nada nos últimos 10 min, FreeRADIUS pode estar fora.
    """
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                  (SELECT COUNT(*) FROM radacct WHERE acctstoptime IS NULL) AS sessoes_ativas,
                  (SELECT COUNT(*) FROM radacct
                    WHERE acctupdatetime > NOW() - INTERVAL '10 minutes'
                       OR acctstarttime  > NOW() - INTERVAL '10 minutes') AS atividade_recente,
                  (SELECT COUNT(*) FROM radpostauth
                    WHERE authdate > NOW() - INTERVAL '10 minutes') AS auths_recentes
            """)
            row = cur.fetchone()
        sessoes = row[0] or 0
        atividade = row[1] or 0
        auths = row[2] or 0
    except Exception as e:
        log.warning("freeradius check db error: %s", e)
        return

    # Se não há sessões nem clientes, não dá pra inferir nada.
    if sessoes == 0:
        _reset_fail(redis_client, "service_down:freeradius")
        return

    # Critério: tem sessões ativas mas zero atividade e zero auths em 10 min = suspeito.
    suspeito = sessoes > 0 and atividade == 0 and auths == 0
    _eval_check(
        notifier, redis_client,
        ok=not suspeito,
        dedup_key="service_down:freeradius",
        fire_msg=(
            f"<b>🔴 FreeRADIUS sem atividade</b>\n"
            f"{sessoes} sessões marcadas como ativas, mas nenhum accounting/auth nos últimos 10 min.\n"
            f"Container caiu ou perdeu conectividade com o MikroTik?"
        ),
        resolve_msg="<b>✅ FreeRADIUS recebendo accounting novamente</b>",
        severity="critical",
    )


# ---------------------------------------------------------------------------
# 4) Sync travado / atrasado
# ---------------------------------------------------------------------------

SYNC_HEARTBEAT_KEY = "sync:last_cycle_at"


def heartbeat_sync_start(redis_client):
    """Chame no início de cada ciclo do sync. Mede atraso entre ciclos."""
    if not redis_client:
        return
    try:
        redis_client.set(SYNC_HEARTBEAT_KEY, datetime.now(timezone.utc).isoformat(), ex=3600)
    except Exception:
        pass


def check_sync_lag(conn, redis_client, notifier, last_cycle_started_at):
    """
    last_cycle_started_at: timestamp UTC do início do ciclo ANTERIOR (passe time.time()).
    Compara com agora; se diff > limiar, alerta.
    """
    if not last_cycle_started_at:
        return
    limiar_min = float(_get_cfg(conn, "alertas_sync_travado_min", "15"))
    diff_s = time.time() - last_cycle_started_at
    diff_min = diff_s / 60

    _eval_check(
        notifier, redis_client,
        ok=diff_min < limiar_min,
        dedup_key="sync_lag",
        fire_msg=(
            f"<b>⏱️ Sync atrasado</b>\n"
            f"Último ciclo demorou {diff_min:.1f} min (limiar {limiar_min:.0f} min).\n"
            f"Investigue rede com SGP, Postgres lento ou containers travados."
        ),
        resolve_msg="<b>✅ Sync com cadência normal</b>",
        severity="warning",
        threshold=1,  # já alerta no primeiro atraso (não tem ciclo "consecutivo" aqui)
    )


# ---------------------------------------------------------------------------
# 5) Sessões PPPoE zumbi (acctstoptime IS NULL + sem update há horas)
# ---------------------------------------------------------------------------

def check_pppoe_zombies(conn, redis_client, notifier):
    """
    Detecta sessões marcadas como ativas no radacct mas que não recebem
    accounting-update há mais de N horas. Causas comuns:
    - MikroTik desconectou o cliente mas o accounting-stop nunca chegou
    - Cliente reconectou e duplicou sessão (duas entradas, uma órfã)
    - Falha de rede entre MikroTik e FreeRADIUS no momento do disconnect
    """
    horas_limiar = float(_get_cfg(conn, "alertas_pppoe_zumbi_horas", "12"))

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    ra.username,
                    ra.nasipaddress::text AS nas_ip,
                    EXTRACT(EPOCH FROM (
                        NOW() - COALESCE(ra.acctupdatetime, ra.acctstarttime)
                    )) / 3600 AS horas_sem_update,
                    c.nome AS cliente_nome
                FROM radacct ra
                LEFT JOIN clientes c ON c.pppoe_login = ra.username
                WHERE ra.acctstoptime IS NULL
                  AND COALESCE(ra.acctupdatetime, ra.acctstarttime) < NOW() - (%s * INTERVAL '1 hour')
                ORDER BY horas_sem_update DESC
                LIMIT 50
            """, (horas_limiar,))
            zombies = cur.fetchall()
    except Exception as e:
        log.warning("zombie check error: %s", e)
        return

    qtd = len(zombies)

    if qtd == 0:
        # Auto-resolve: se havia firing, manda "voltou ao normal"
        notifier.resolve(
            "pppoe_zombies:summary",
            msg="<b>✅ Sem sessões PPPoE zumbis</b>",
        )
        return

    # Top 5 mais antigas
    top = zombies[:5]
    lista = "\n".join(
        f"• <code>{z['username']}</code> ({z['cliente_nome'] or '?'}) — "
        f"{float(z['horas_sem_update'] or 0):.0f}h sem update, NAS {z['nas_ip']}"
        for z in top
    )
    extra = f"\n<i>+ {qtd - 5} outras...</i>" if qtd > 5 else ""

    notifier.fire(
        "pppoe_zombies:summary",
        (
            f"<b>⚠️ {qtd} sessão(ões) PPPoE zumbi</b>\n"
            f"<i>Sem accounting-update há &gt; {horas_limiar:.0f}h:</i>\n"
            f"{lista}{extra}\n\n"
            f"<i>Limpe via painel ou rode UPDATE radacct SET acctstoptime=NOW() "
            f"WHERE acctstoptime IS NULL AND acctupdatetime &lt; NOW() - INTERVAL '{horas_limiar:.0f} hours';</i>"
        ),
        severity="warning",
        cooldown=3600,  # 1 hora
    )


# ---------------------------------------------------------------------------
# Orquestrador principal
# ---------------------------------------------------------------------------

def run_health_checks(conn, redis_client, notifier, last_cycle_started_at=None):
    """Roda todos os checks de infra. Chamado uma vez por ciclo do sync."""
    try:
        check_external_services(conn, redis_client, notifier)
    except Exception as e:
        log.warning("check_external_services error: %s", e)

    try:
        check_nas_health(conn, redis_client, notifier)
    except Exception as e:
        log.warning("check_nas_health error: %s", e)

    try:
        check_freeradius(conn, redis_client, notifier)
    except Exception as e:
        log.warning("check_freeradius error: %s", e)

    try:
        check_pppoe_zombies(conn, redis_client, notifier)
    except Exception as e:
        log.warning("check_pppoe_zombies error: %s", e)

    try:
        check_sync_lag(conn, redis_client, notifier, last_cycle_started_at)
    except Exception as e:
        log.warning("check_sync_lag error: %s", e)
