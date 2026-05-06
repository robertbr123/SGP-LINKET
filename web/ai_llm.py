"""
Análise contextual via LLM — abstração multi-provider.

Providers suportados:
1. github     — GitHub Models (grátis, ~50 req/dia)        → GITHUB_TOKEN
2. cloudflare — Cloudflare Workers AI (grátis ~10k/dia)    → CF_ACCOUNT_ID + CF_AI_TOKEN
3. anthropic  — Anthropic API (pago)                       → ANTHROPIC_API_KEY
4. openai     — OpenAI API (pago)                          → OPENAI_API_KEY
5. groq       — Groq (grátis com rate limit)               → GROQ_API_KEY

Auto-detecta o provider baseado em qual env var está setada.
Falha silenciosa: se nenhum provider configurado, retorna None
(o resumo segue sem análise IA).
"""
import os
import json
import logging
import requests
import psycopg2.extras

log = logging.getLogger("ai_summary")


# ---------------------------------------------------------------------------
# Auto-seleção de provider
# ---------------------------------------------------------------------------

def _detect_provider():
    """Retorna (provider_name, config_dict) baseado em env vars setadas."""
    # Override explícito
    forced = os.environ.get("AI_PROVIDER", "").strip().lower()
    if forced:
        return forced, _config_for(forced)

    # Auto-detecção (em ordem de preferência: gratuitos primeiro)
    if os.environ.get("GITHUB_TOKEN", "").strip():
        return "github", _config_for("github")
    if os.environ.get("CF_AI_TOKEN", "").strip() and os.environ.get("CF_ACCOUNT_ID", "").strip():
        return "cloudflare", _config_for("cloudflare")
    if os.environ.get("GROQ_API_KEY", "").strip():
        return "groq", _config_for("groq")
    if os.environ.get("ANTHROPIC_API_KEY", "").strip():
        return "anthropic", _config_for("anthropic")
    if os.environ.get("OPENAI_API_KEY", "").strip():
        return "openai", _config_for("openai")
    return None, None


def _config_for(provider):
    if provider == "github":
        return {
            "url":   "https://models.inference.ai.azure.com/chat/completions",
            "key":   os.environ.get("GITHUB_TOKEN", ""),
            "model": os.environ.get("AI_MODEL", "openai/gpt-4o-mini"),
            "auth":  "bearer",
        }
    if provider == "cloudflare":
        account = os.environ.get("CF_ACCOUNT_ID", "")
        model = os.environ.get("AI_MODEL", "@cf/meta/llama-3.3-70b-instruct-fp8-fast")
        return {
            "url":   f"https://api.cloudflare.com/client/v4/accounts/{account}/ai/run/{model}",
            "key":   os.environ.get("CF_AI_TOKEN", ""),
            "model": model,
            "auth":  "bearer",
            "shape": "cloudflare",
        }
    if provider == "groq":
        return {
            "url":   "https://api.groq.com/openai/v1/chat/completions",
            "key":   os.environ.get("GROQ_API_KEY", ""),
            "model": os.environ.get("AI_MODEL", "llama-3.3-70b-versatile"),
            "auth":  "bearer",
        }
    if provider == "anthropic":
        return {
            "url":   "https://api.anthropic.com/v1/messages",
            "key":   os.environ.get("ANTHROPIC_API_KEY", ""),
            "model": os.environ.get("AI_MODEL", "claude-haiku-4-5-20251001"),
            "auth":  "anthropic",
        }
    if provider == "openai":
        return {
            "url":   "https://api.openai.com/v1/chat/completions",
            "key":   os.environ.get("OPENAI_API_KEY", ""),
            "model": os.environ.get("AI_MODEL", "gpt-4o-mini"),
            "auth":  "bearer",
        }
    return None


# ---------------------------------------------------------------------------
# Chamada genérica
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = (
    "Você é um analista de operações de um ISP (provedor de internet). "
    "Receberá dados estruturados em JSON sobre clientes, alertas, CPEs e consumo. "
    "Escreva uma análise CURTA (máximo 5 linhas) em português, destacando: "
    "(1) o que importa de fato, (2) anomalias ou padrões preocupantes, "
    "(3) UMA ação sugerida concreta se houver. Use tom direto, sem floreios. "
    "Não repita os números brutos — interprete-os. "
    "Se tudo estiver normal, diga em uma frase. "
    "Use HTML simples do Telegram: <b>negrito</b>, <i>itálico</i>. NÃO use markdown."
)


def _call_llm(system_prompt, user_prompt, max_tokens=400):
    provider, cfg = _detect_provider()
    if not cfg or not cfg.get("key"):
        return None

    try:
        if cfg["auth"] == "anthropic":
            # Anthropic tem API distinta
            r = requests.post(
                cfg["url"],
                headers={
                    "x-api-key": cfg["key"],
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": cfg["model"],
                    "max_tokens": max_tokens,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_prompt}],
                },
                timeout=20,
            )
            if r.ok:
                data = r.json()
                if data.get("content"):
                    return data["content"][0].get("text", "").strip()
            log.warning("Anthropic HTTP %s: %s", r.status_code, r.text[:200])
            return None

        if cfg.get("shape") == "cloudflare":
            # CF Workers AI tem shape próprio
            r = requests.post(
                cfg["url"],
                headers={
                    "Authorization": f"Bearer {cfg['key']}",
                    "Content-Type": "application/json",
                },
                json={
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "max_tokens": max_tokens,
                },
                timeout=20,
            )
            if r.ok:
                data = r.json()
                # CF retorna {"result": {"response": "..."}}
                if data.get("success") and data.get("result"):
                    return data["result"].get("response", "").strip()
            log.warning("CF Workers AI HTTP %s: %s", r.status_code, r.text[:200])
            return None

        # Padrão OpenAI-compatible (GitHub Models, Groq, OpenAI)
        r = requests.post(
            cfg["url"],
            headers={
                "Authorization": f"Bearer {cfg['key']}",
                "Content-Type": "application/json",
            },
            json={
                "model": cfg["model"],
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "max_tokens": max_tokens,
                "temperature": 0.3,
            },
            timeout=20,
        )
        if r.ok:
            data = r.json()
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "").strip()
        log.warning("%s HTTP %s: %s", provider, r.status_code, r.text[:200])
    except Exception as e:
        log.warning("%s error: %s", provider, e)
    return None


# ---------------------------------------------------------------------------
# Coleta de contexto (igual antes)
# ---------------------------------------------------------------------------

def _gather_context(conn):
    ctx = {}
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT
                  (SELECT COUNT(*) FROM clientes) AS total_clientes,
                  (SELECT COUNT(*) FROM clientes WHERE status='ativo')    AS ativos,
                  (SELECT COUNT(*) FROM clientes WHERE status='suspenso') AS suspensos,
                  (SELECT COUNT(*) FROM cpe_devices WHERE online=FALSE)   AS cpes_offline,
                  (SELECT COUNT(*) FROM chamados WHERE status='aberto')   AS chamados_abertos,
                  (SELECT COUNT(*) FROM alert_state WHERE firing=TRUE)    AS alertas_firing,
                  (SELECT COUNT(*) FROM alert_state WHERE firing=FALSE
                     AND ultima_vez > NOW() - INTERVAL '24 hours')        AS alertas_resolvidos_24h,
                  (SELECT COUNT(*) FROM chamados WHERE criado_em > NOW() - INTERVAL '24 hours') AS chamados_24h,
                  (SELECT COUNT(*) FROM chamados WHERE resolvido_em > NOW() - INTERVAL '24 hours'
                     AND status='resolvido')                              AS resolvidos_24h
            """)
            ctx["kpis"] = dict(cur.fetchone())
            cur.execute("""
                SELECT dedup_key, event_type, severity, count_total, last_sent_at::text AS ts
                  FROM alert_state
                 WHERE last_sent_at > NOW() - INTERVAL '24 hours'
                   AND severity IN ('critical', 'warning')
              ORDER BY count_total DESC, last_sent_at DESC LIMIT 15
            """)
            ctx["alertas_recentes"] = [dict(r) for r in cur.fetchall()]
            cur.execute("""
                SELECT COALESCE(c.nome, ra.username) AS nome,
                       SUM(COALESCE(ra.acctinputoctets,0) + COALESCE(ra.acctoutputoctets,0))::bigint AS bytes
                  FROM radacct ra LEFT JOIN clientes c ON c.pppoe_login = ra.username
                 WHERE COALESCE(ra.acctupdatetime, ra.acctstarttime) > NOW() - INTERVAL '24 hours'
              GROUP BY c.nome, ra.username ORDER BY bytes DESC LIMIT 5
            """)
            ctx["top_consumo"] = [{"nome": r["nome"], "gb": round((r["bytes"] or 0) / 1073741824, 1)} for r in cur.fetchall()]
            try:
                cur.execute("""
                    SELECT cpe.id, c.nome, cpe.rx_power
                      FROM cpe_devices cpe LEFT JOIN clientes c ON c.id = cpe.cliente_id
                     WHERE cpe.rx_power IS NOT NULL AND cpe.rx_power < -24
                  ORDER BY cpe.rx_power ASC LIMIT 10
                """)
                ctx["cpes_sinal_baixo"] = [dict(r) for r in cur.fetchall()]
            except Exception:
                ctx["cpes_sinal_baixo"] = []
    except Exception as e:
        log.warning("ai_summary gather error: %s", e)
        return None
    return ctx


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------

def generate_morning_analysis(conn):
    provider, cfg = _detect_provider()
    if not cfg or not cfg.get("key"):
        return None
    ctx = _gather_context(conn)
    if not ctx:
        return None
    user_prompt = (
        "Dados das últimas 24h:\n```json\n"
        + json.dumps(ctx, ensure_ascii=False, default=str, indent=2)
        + "\n```\nFaça sua análise de operação ISP."
    )
    text = _call_llm(SYSTEM_PROMPT, user_prompt, max_tokens=300)
    if not text:
        return None
    return f"\n\n<b>🤖 Análise IA</b> <i>({provider})</i>\n{text}"


def generate_shift_analysis(conn):
    provider, cfg = _detect_provider()
    if not cfg or not cfg.get("key"):
        return None
    ctx = _gather_context(conn)
    if not ctx:
        return None
    user_prompt = (
        "Resumo do turno (últimas ~10h):\n```json\n"
        + json.dumps(ctx, ensure_ascii=False, default=str, indent=2)
        + "\n```\n"
        "Foque em: incidentes do turno, eficiência da equipe (MTTR), pendências pro próximo turno."
    )
    text = _call_llm(SYSTEM_PROMPT, user_prompt, max_tokens=300)
    if not text:
        return None
    return f"\n\n<b>🤖 Análise do Turno</b> <i>({provider})</i>\n{text}"
