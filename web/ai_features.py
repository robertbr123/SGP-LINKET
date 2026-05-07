"""
Recursos avançados de IA:
- ai_search   — busca em linguagem natural com SQL seguro (structured output)
- ai_briefing — resumo do dia ao abrir Mini App
- ai_dictate  — transcrição via Whisper + estruturação em campos de form
- ai_release  — release notes via webhook GitHub
"""
import os
import json
import logging
import requests
import psycopg2.extras
from datetime import datetime, date

from ai_llm import _detect_provider, _call_llm, SYSTEM_PROMPT as _DEFAULT_PROMPT

log = logging.getLogger("ai_features")


# ===========================================================================
# Whitelist de schema — único lugar que controla o que IA pode acessar
# ===========================================================================

ALLOWED_TABLES = {
    "clientes": {
        "columns": ["id", "nome", "cpf", "pppoe_login", "ip", "plano",
                    "velocidade_down", "velocidade_up", "status",
                    "criado_em", "atualizado_em", "ultimo_sync_em"],
        "join": None,
    },
    "cpe_devices": {
        "columns": ["id", "cliente_id", "modelo", "fabricante", "online",
                    "rx_power", "ip_wan", "serial_number", "ultima_conexao",
                    "criado_em", "atualizado_em"],
        "join": "LEFT JOIN clientes c ON c.id = cpe_devices.cliente_id",
    },
    "nas": {
        "columns": ["id", "nasname", "shortname", "description"],
        "join": None,
    },
    "chamados": {
        "columns": ["id", "cpe_id", "cliente_id", "tipo", "status",
                    "descricao", "criado_em", "resolvido_em", "atualizado_em"],
        "join": None,
    },
    "alert_state": {
        "columns": ["dedup_key", "event_type", "severity", "firing",
                    "primeira_vez", "ultima_vez", "count_total"],
        "join": None,
    },
    "audit_log": {
        "columns": ["id", "ts", "usuario_nome", "ip", "action",
                    "target_type", "target_id"],
        "join": None,
    },
    "radacct": {
        "columns": ["username", "acctstarttime", "acctstoptime",
                    "acctinputoctets", "acctoutputoctets", "framedipaddress",
                    "nasipaddress"],
        "join": None,
    },
}

ALLOWED_OPS = {"=", "!=", "<>", ">", ">=", "<", "<=",
               "LIKE", "ILIKE", "IN", "IS NULL", "IS NOT NULL"}

MAX_LIMIT = 200


# ===========================================================================
# 1) Busca natural com SQL seguro
# ===========================================================================

SEARCH_SYSTEM_PROMPT = (
    "Você é um conversor de linguagem natural para queries estruturadas em um sistema "
    "de provedor de internet (ISP). Receberá uma pergunta em português e o schema das tabelas. "
    "Devolva APENAS um JSON com este formato (sem markdown, sem texto extra):\n"
    "{\n"
    '  "table": "<nome_tabela_principal>",\n'
    '  "filters": [{"field": "<col>", "op": "<op>", "value": "<valor ou null>"}, ...],\n'
    '  "order_by": "<col DESC>" (opcional),\n'
    '  "limit": <numero, max 200>,\n'
    '  "explanation": "<frase curta explicando o que vai retornar>"\n'
    "}\n"
    "Operadores válidos: =, !=, >, >=, <, <=, LIKE, ILIKE, IN, IS NULL, IS NOT NULL.\n"
    "Use ILIKE para texto. Use formato 'YYYY-MM-DD' para datas.\n"
    "Para 'há mais de N dias', use op '<' com NOW() - INTERVAL — mas como JSON não suporta SQL, "
    "use formato especial: {'field': 'criado_em', 'op': '<', 'value': 'NOW() - INTERVAL X days'}\n"
    "Se a pergunta for vaga ou inválida, retorne {'error': 'mensagem explicando'}.\n"
    "Use SOMENTE tabelas e colunas listadas no schema fornecido.\n"
    "NUNCA gere SQL, NUNCA use JOIN manual — só preencha 'table' e 'filters'."
)


def _build_safe_sql(spec):
    """
    Converte JSON da IA em SQL parametrizado.
    Levanta ValueError se algum campo violar whitelist.
    Retorna (sql_string, params_list).
    """
    table = spec.get("table")
    if table not in ALLOWED_TABLES:
        raise ValueError(f"tabela não permitida: {table}")

    cols = ALLOWED_TABLES[table]["columns"]
    join = ALLOWED_TABLES[table]["join"]

    select_cols = ", ".join(f"{table}.{c}" for c in cols)
    sql = f"SELECT {select_cols} FROM {table}"
    if join:
        sql += f" {join}"

    params = []
    where_parts = []
    for f in spec.get("filters", []) or []:
        field = f.get("field")
        op = (f.get("op") or "=").upper().strip()
        value = f.get("value")

        if field not in cols:
            raise ValueError(f"coluna não permitida: {table}.{field}")
        if op not in ALLOWED_OPS:
            raise ValueError(f"operador não permitido: {op}")

        # Casos especiais sem valor
        if op in ("IS NULL", "IS NOT NULL"):
            where_parts.append(f"{table}.{field} {op}")
            continue

        # Suporte a NOW() - INTERVAL X days (sem permitir SQL arbitrário)
        if isinstance(value, str) and value.startswith("NOW() - INTERVAL "):
            # Permite só dígitos + " days/hours/minutes"
            import re as _re
            m = _re.match(r"NOW\(\) - INTERVAL (\d+) (days?|hours?|minutes?)", value)
            if m:
                where_parts.append(f"{table}.{field} {op} (NOW() - INTERVAL '{m.group(1)} {m.group(2)}')")
                continue
            else:
                raise ValueError(f"valor inválido pra INTERVAL: {value}")

        # IN — value precisa ser lista
        if op == "IN":
            if not isinstance(value, list) or not value:
                raise ValueError("IN requer lista não vazia")
            placeholders = ", ".join(["%s"] * len(value))
            where_parts.append(f"{table}.{field} IN ({placeholders})")
            params.extend(value)
            continue

        # Padrão
        where_parts.append(f"{table}.{field} {op} %s")
        params.append(value)

    if where_parts:
        sql += " WHERE " + " AND ".join(where_parts)

    # ORDER BY validado
    order = spec.get("order_by")
    if order:
        # Aceita formato "col" ou "col DESC"
        parts = order.strip().split()
        if parts[0] in cols and (len(parts) == 1 or parts[1].upper() in ("ASC", "DESC")):
            sql += f" ORDER BY {table}.{parts[0]}"
            if len(parts) > 1:
                sql += " " + parts[1].upper()

    limit = min(int(spec.get("limit", 50)), MAX_LIMIT)
    sql += f" LIMIT {limit}"

    return sql, params


def ai_search(get_db, pergunta):
    """
    Recebe pergunta em PT-BR. Retorna dict com:
      - 'rows': lista de resultados (ou [])
      - 'sql': SQL gerado (pra debug/transparência)
      - 'spec': JSON da IA
      - 'explanation': texto explicando o que retornou
      - 'error': se algo falhou
    """
    if not pergunta or len(pergunta.strip()) < 3:
        return {"error": "pergunta muito curta"}

    schema_text = "Tabelas e colunas permitidas:\n" + "\n".join(
        f"- {t}: {', '.join(meta['columns'])}" for t, meta in ALLOWED_TABLES.items()
    )

    user_prompt = f"{schema_text}\n\nPergunta: {pergunta}"
    raw = _call_llm(SEARCH_SYSTEM_PROMPT, user_prompt, max_tokens=600)
    if not raw:
        return {"error": "IA não respondeu"}

    # Tenta parsear JSON (pode vir com cercas markdown)
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.strip("`").lstrip("json").strip()
    try:
        spec = json.loads(raw)
    except json.JSONDecodeError as e:
        return {"error": f"IA retornou JSON inválido: {e}", "raw": raw[:300]}

    if "error" in spec:
        return {"error": spec["error"], "spec": spec}

    try:
        sql, params = _build_safe_sql(spec)
    except ValueError as e:
        return {"error": f"validação falhou: {e}", "spec": spec}

    # Executa
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()
    except Exception as e:
        return {"error": f"erro SQL: {e}", "spec": spec, "sql": sql}
    finally:
        conn.close()

    # Serializa datas
    out_rows = []
    for r in rows:
        d = dict(r)
        for k, v in d.items():
            if hasattr(v, "isoformat"):
                d[k] = v.isoformat()
        out_rows.append(d)

    return {
        "rows": out_rows,
        "total": len(out_rows),
        "sql": sql,
        "spec": spec,
        "explanation": spec.get("explanation", ""),
    }


# ===========================================================================
# 2) Briefing matinal
# ===========================================================================

def _last_brief_for_user(get_db, telegram_user_id):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT MAX(ts)::date FROM audit_log
                 WHERE action = 'miniapp:briefing_shown'
                   AND target_id = %s
            """, (str(telegram_user_id),))
            row = cur.fetchone()
        conn.close()
        return row[0] if row and row[0] else None
    except Exception:
        return None


def _record_brief_shown(get_db, telegram_user_id):
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_log (usuario_nome, action, target_type, target_id)
                VALUES (%s, 'miniapp:briefing_shown', 'briefing', %s)
            """, (f"miniapp:{telegram_user_id}", str(telegram_user_id)))
        conn.commit()
        conn.close()
    except Exception as e:
        log.warning("record briefing failed: %s", e)


BRIEFING_SYSTEM = (
    "Você é um analista resumindo o estado de um ISP em UMA frase de no máximo 25 palavras. "
    "Tom: amigável, direto. Se tudo normal, diga isso. Se tem algo, destaque o mais importante. "
    "Use 1 emoji no início. Não use HTML."
)


def ai_briefing(get_db, telegram_user_id, force=False):
    """
    Retorna briefing curto pro user. Se já mostrou hoje E force=False, retorna None.
    """
    if not force:
        last = _last_brief_for_user(get_db, telegram_user_id)
        if last == date.today():
            return None

    # Coleta contexto rápido
    try:
        conn = get_db()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT
                  (SELECT COUNT(*) FROM alert_state WHERE firing=TRUE) AS firing,
                  (SELECT COUNT(*) FROM chamados WHERE status='aberto') AS chamados_abertos,
                  (SELECT COUNT(*) FROM cpe_devices WHERE online=FALSE) AS cpes_off,
                  (SELECT COUNT(*) FROM clientes) AS total_clientes,
                  (SELECT COUNT(*) FROM audit_log WHERE ts > NOW() - INTERVAL '24 hours') AS eventos_24h
            """)
            kpis = dict(cur.fetchone())
        conn.close()
    except Exception:
        return None

    user_prompt = (
        "Estado do sistema agora:\n"
        f"```json\n{json.dumps(kpis, indent=2)}\n```\n"
        "Faça o briefing curto."
    )
    text = _call_llm(BRIEFING_SYSTEM, user_prompt, max_tokens=80)
    if not text:
        return None

    _record_brief_shown(get_db, telegram_user_id)
    return text


# ===========================================================================
# 3) Ditar — Whisper + estruturação
# ===========================================================================

def transcribe_audio(audio_bytes, content_type="audio/webm"):
    """
    Whisper API da OpenAI (precisa OPENAI_API_KEY).
    Retorna texto transcrito ou None.
    """
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None
    try:
        files = {"file": ("audio.webm", audio_bytes, content_type)}
        data = {"model": "whisper-1", "language": "pt"}
        r = requests.post(
            "https://api.openai.com/v1/audio/transcriptions",
            headers={"Authorization": f"Bearer {api_key}"},
            files=files,
            data=data,
            timeout=60,
        )
        if r.ok:
            return r.json().get("text", "").strip()
        log.warning("Whisper HTTP %s: %s", r.status_code, r.text[:200])
    except Exception as e:
        log.warning("Whisper error: %s", e)
    return None


STRUCTURE_SYSTEM = (
    "Você recebe um texto ditado e precisa extrair os campos solicitados. "
    "Retorne APENAS JSON com os campos pedidos, sem texto extra. "
    "Para CPF/CNPJ, normalize só dígitos. Para nomes, capitalize corretamente. "
    "Se um campo não foi mencionado, omita do JSON (não invente)."
)


def structure_dictation(texto, fields):
    """
    fields: lista de {"name": "cpf", "description": "CPF (11 dígitos)"}.
    Retorna dict com os campos extraídos do texto.
    """
    if not texto:
        return {}
    fields_desc = "\n".join(f"- {f['name']}: {f.get('description', '')}" for f in fields)
    prompt = f"Texto ditado: {texto}\n\nCampos a extrair:\n{fields_desc}"
    raw = _call_llm(STRUCTURE_SYSTEM, prompt, max_tokens=300)
    if not raw:
        return {}
    raw = raw.strip().strip("`").lstrip("json").strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


# ===========================================================================
# 4) Release notes via webhook GitHub
# ===========================================================================

RELEASE_SYSTEM = (
    "Você é um redator de release notes para clientes finais de um ISP. "
    "Receberá uma lista de commits (mensagens do git). "
    "Escreva um post CURTO (máximo 4 linhas) em português destacando o que MELHORA pro cliente. "
    "Ignore commits técnicos puros (refactor, fix typo). "
    "Foque em: novas funcionalidades, melhorias de estabilidade, correções perceptíveis. "
    "Tom: amigável, sem jargão técnico. "
    "Use HTML do Telegram: <b>negrito</b>, emojis. "
    "Se nenhum commit for relevante pro cliente, retorne string vazia."
)


def generate_release_notes(commits):
    """
    commits: lista de dicts {"message": "...", "author": "...", "url": "..."}
    Retorna string (ou vazio).
    """
    if not commits:
        return ""
    msgs = "\n".join(f"- {c.get('message', '').splitlines()[0][:120]}" for c in commits)
    prompt = f"Commits do push:\n{msgs}"
    text = _call_llm(RELEASE_SYSTEM, prompt, max_tokens=250)
    return text or ""


# ===========================================================================
# Fase Q — Diagnóstico cliente + Resumo dashboard
# ===========================================================================

DIAG_SYSTEM = (
    "Você é um analista nível 2 de suporte de ISP. Receberá os dados completos de um cliente "
    "(status, sessão atual, CPE, histórico de eventos, alertas relacionados). "
    "Sua tarefa: dar um PARECER CURTO (máximo 6 linhas) em português, com:\n"
    "1) Estado real do cliente (1 linha)\n"
    "2) Causa provável de qualquer problema detectado (1-2 linhas)\n"
    "3) AÇÃO SUGERIDA concreta — pode ser técnica (visita, reboot, troca de pigtail) "
    "ou administrativa (cobrar pagamento). Se nada errado, diga 'tudo normal'.\n"
    "Tom: direto, sem floreios. Use HTML do Telegram: <b>, <i>. Sem markdown."
)


def ai_diagnose_client(get_db, cliente_id):
    """Coleta tudo sobre o cliente e devolve parecer da IA."""
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT c.*, p.nome AS plano_nome
                  FROM clientes c LEFT JOIN planos p ON p.id = c.plano_id
                 WHERE c.id = %s
            """, (cliente_id,))
            cli = cur.fetchone()
            if not cli:
                return {"error": "cliente não encontrado"}

            cur.execute("""
                SELECT acctstarttime, acctstoptime, acctsessiontime,
                       acctinputoctets, acctoutputoctets,
                       framedipaddress::text AS ip, nasipaddress::text AS nas,
                       acctterminatecause
                  FROM radacct
                 WHERE username = %s
              ORDER BY acctstarttime DESC LIMIT 5
            """, (cli["pppoe_login"],))
            sessoes = cur.fetchall()

            cur.execute("""
                SELECT id, modelo, fabricante, online, rx_power, ip_wan, ultima_conexao
                  FROM cpe_devices WHERE cliente_id = %s LIMIT 1
            """, (cliente_id,))
            cpe = cur.fetchone()

            cpe_eventos = []
            if cpe:
                cur.execute("""
                    SELECT event_type, detail, criado_em
                      FROM cpe_events WHERE cpe_id = %s
                  ORDER BY criado_em DESC LIMIT 10
                """, (cpe["id"],))
                cpe_eventos = cur.fetchall()

            cur.execute("""
                SELECT tipo, status, descricao, criado_em
                  FROM chamados WHERE cliente_id = %s
              ORDER BY criado_em DESC LIMIT 5
            """, (cliente_id,))
            chamados_hist = cur.fetchall()
    finally:
        conn.close()

    contexto = {
        "cliente": {k: (str(v) if hasattr(v, "isoformat") else v) for k, v in dict(cli).items()},
        "sessoes_recentes": [
            {k: (str(v) if hasattr(v, "isoformat") else v) for k, v in dict(s).items()}
            for s in sessoes
        ],
        "cpe": {k: (str(v) if hasattr(v, "isoformat") else v) for k, v in dict(cpe).items()} if cpe else None,
        "cpe_eventos_recentes": [
            {k: (str(v) if hasattr(v, "isoformat") else v) for k, v in dict(e).items()}
            for e in cpe_eventos
        ],
        "chamados_recentes": [
            {k: (str(v) if hasattr(v, "isoformat") else v) for k, v in dict(ch).items()}
            for ch in chamados_hist
        ],
    }

    prompt = (
        "Analise este cliente:\n```json\n"
        + json.dumps(contexto, ensure_ascii=False, indent=2, default=str)
        + "\n```"
    )
    text = _call_llm(DIAG_SYSTEM, prompt, max_tokens=400)
    return {"parecer": text or "IA não respondeu", "contexto_enviado": True}


DASHBOARD_SUMMARY_SYSTEM = (
    "Você é um operador de NOC sintetizando o estado de um ISP em UMA frase. "
    "Máximo 25 palavras. Foque no que IMPORTA agora. "
    "Se tudo normal, diga isso. Se tem coisa pra atenção, destaque. "
    "Use 1 emoji no início. Sem HTML."
)


def ai_dashboard_summary(get_db):
    """Resumo de 1 frase pro topo do dashboard."""
    try:
        conn = get_db()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT
                  (SELECT COUNT(*) FROM clientes) AS total,
                  (SELECT COUNT(*) FROM clientes WHERE status='suspenso') AS suspensos,
                  (SELECT COUNT(*) FROM cpe_devices WHERE online=FALSE) AS cpes_off,
                  (SELECT COUNT(*) FROM chamados WHERE status='aberto') AS chamados,
                  (SELECT COUNT(*) FROM alert_state WHERE firing=TRUE) AS firing,
                  (SELECT COUNT(*) FROM consumo_anomalias WHERE ignorado=FALSE
                     AND detectado_em > NOW() - INTERVAL '24 hours') AS anomalias
            """)
            kpis = dict(cur.fetchone())
        conn.close()
    except Exception:
        return None

    prompt = f"Estado agora:\n```json\n{json.dumps(kpis, indent=2)}\n```"
    return _call_llm(DASHBOARD_SUMMARY_SYSTEM, prompt, max_tokens=80)


# ===========================================================================
# Fase R — Chamados (sugestão + classificação)
# ===========================================================================

CHAMADO_SUGGEST_SYSTEM = (
    "Você é um técnico sênior de ISP. Receberá um chamado novo. "
    "Devolva sugestão CURTA de resolução (máximo 4 linhas):\n"
    "1) Causa provável (1 linha)\n"
    "2) Passos pra resolver, ordenados (3 passos no máximo)\n"
    "Se houver chamados similares já resolvidos, considere o que funcionou neles. "
    "Use HTML do Telegram: <b>, <i>. Sem markdown. Tom: direto, prático."
)


def ai_suggest_chamado_fix(get_db, chamado_id):
    """Sugere resolução pra um chamado específico baseado em histórico similar."""
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT ch.*, c.nome AS cliente_nome, c.pppoe_login,
                       cpe.modelo, cpe.fabricante, cpe.online AS cpe_online,
                       cpe.rx_power
                  FROM chamados ch
                  LEFT JOIN clientes c ON c.id = ch.cliente_id
                  LEFT JOIN cpe_devices cpe ON cpe.id = ch.cpe_id
                 WHERE ch.id = %s
            """, (chamado_id,))
            ch = cur.fetchone()
            if not ch:
                return {"error": "chamado não encontrado"}

            # Busca chamados similares JÁ RESOLVIDOS (mesmo tipo)
            cur.execute("""
                SELECT descricao, EXTRACT(EPOCH FROM (resolvido_em - criado_em))/60 AS mttr_min
                  FROM chamados
                 WHERE tipo = %s AND status = 'resolvido'
              ORDER BY resolvido_em DESC LIMIT 5
            """, (ch["tipo"],))
            similares = cur.fetchall()
    finally:
        conn.close()

    contexto = {
        "chamado_atual": {k: (str(v) if hasattr(v, "isoformat") else v) for k, v in dict(ch).items()},
        "chamados_similares_resolvidos": [
            {k: (str(v) if hasattr(v, "isoformat") else v) for k, v in dict(s).items()}
            for s in similares
        ],
    }
    prompt = "Chamado:\n```json\n" + json.dumps(contexto, ensure_ascii=False, indent=2, default=str) + "\n```"
    text = _call_llm(CHAMADO_SUGGEST_SYSTEM, prompt, max_tokens=300)
    return {"sugestao": text or "IA não respondeu"}


CHAMADO_CLASSIFY_SYSTEM = (
    "Você é um classificador de chamados de ISP. Receberá descrição + tipo de um chamado. "
    "Devolva APENAS uma das categorias (1 palavra, lowercase):\n"
    "- falha-fibra (problemas de sinal óptico, queda fibra, drop)\n"
    "- equip-cliente (CPE travado, roteador defeituoso, cabo solto na casa)\n"
    "- config-mikrotik (problema de NAS, routing, autenticação)\n"
    "- inadimplencia (pagamento atrasado, suspensão)\n"
    "- demanda-cliente (mudança de plano, cancelamento, pedido de visita)\n"
    "- outros\n"
    "Responda SÓ a categoria, sem texto extra, sem aspas."
)


VALID_CATEGORIES = {
    "falha-fibra", "equip-cliente", "config-mikrotik",
    "inadimplencia", "demanda-cliente", "outros"
}


def ai_classify_chamado(get_db, chamado_id, persist=True):
    """Classifica um chamado em categoria pré-definida."""
    conn = get_db()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT id, tipo, descricao, ai_categoria
                  FROM chamados WHERE id = %s
            """, (chamado_id,))
            ch = cur.fetchone()
            if not ch:
                return None
            if ch["ai_categoria"]:
                return ch["ai_categoria"]  # já classificado
    finally:
        conn.close()

    prompt = f"Tipo: {ch['tipo']}\nDescrição: {ch['descricao']}"
    raw = _call_llm(CHAMADO_CLASSIFY_SYSTEM, prompt, max_tokens=20)
    if not raw:
        return None
    cat = raw.strip().lower().split()[0] if raw.strip() else "outros"
    if cat not in VALID_CATEGORIES:
        cat = "outros"

    if persist:
        try:
            conn = get_db()
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE chamados
                       SET ai_categoria = %s, ai_classificado_em = NOW()
                     WHERE id = %s
                """, (cat, chamado_id))
            conn.commit()
            conn.close()
        except Exception as e:
            log.warning("classify persist failed: %s", e)
    return cat


# ===========================================================================
# Fase S — Detecção de anomalia de consumo (sem IA, matemática pura)
# ===========================================================================

def detect_consumo_anomalies(get_db):
    """
    Pra cada cliente com pppoe_login:
    - Calcula GB consumidos nos últimos 7 dias
    - Calcula média e stddev nos 30 dias anteriores (excluindo os últimos 7)
    - Se z-score > limiar configurado, registra em consumo_anomalias.

    Roda no sync.py 1x/dia (junto com resumos).
    Retorna lista de anomalias detectadas nesta execução.
    """
    detectadas = []
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("SELECT valor FROM alertas_config WHERE chave='anomalia_zscore_min'")
            row = cur.fetchone()
            zscore_min = float(row[0]) if row else 3.0
            cur.execute("SELECT valor FROM alertas_config WHERE chave='anomalia_consumo_min_gb'")
            row = cur.fetchone()
            consumo_min = float(row[0]) if row else 20.0

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                WITH consumo_7d AS (
                    SELECT username,
                           SUM(COALESCE(acctinputoctets,0)+COALESCE(acctoutputoctets,0))/1073741824.0 AS gb
                      FROM radacct
                     WHERE COALESCE(acctupdatetime, acctstarttime) > NOW() - INTERVAL '7 days'
                  GROUP BY username
                ),
                consumo_baseline AS (
                    SELECT username,
                           AVG(daily_gb) AS media,
                           STDDEV(daily_gb) AS stdv
                      FROM (
                          SELECT username,
                                 date_trunc('day', COALESCE(acctupdatetime, acctstarttime)) AS dia,
                                 SUM(COALESCE(acctinputoctets,0)+COALESCE(acctoutputoctets,0))/1073741824.0 AS daily_gb
                            FROM radacct
                           WHERE COALESCE(acctupdatetime, acctstarttime)
                                 BETWEEN NOW() - INTERVAL '37 days' AND NOW() - INTERVAL '7 days'
                        GROUP BY username, dia
                      ) t
                  GROUP BY username
                  HAVING COUNT(*) >= 7
                )
                SELECT c.id AS cliente_id, c.nome, c.pppoe_login,
                       c7.gb AS atual_gb,
                       cb.media * 7 AS esperado_7d,  -- baseline diária * 7
                       cb.stdv * SQRT(7) AS sigma_7d,
                       CASE WHEN cb.stdv > 0
                            THEN (c7.gb - cb.media * 7) / (cb.stdv * SQRT(7))
                            ELSE 0
                       END AS zscore
                  FROM consumo_7d c7
                  JOIN consumo_baseline cb ON cb.username = c7.username
                  JOIN clientes c ON c.pppoe_login = c7.username
                 WHERE c7.gb > %s
                   AND cb.media > 0
                   AND (c7.gb - cb.media * 7) / (cb.stdv * SQRT(7)) > %s
              ORDER BY zscore DESC
                 LIMIT 50
            """, (consumo_min, zscore_min))
            rows = cur.fetchall()

        for r in rows:
            zscore = float(r["zscore"] or 0)
            severidade = "critical" if zscore > 5 else "warning"
            with conn.cursor() as cur:
                # Evita duplicar — só insere se não houve detecção recente do mesmo cliente
                cur.execute("""
                    INSERT INTO consumo_anomalias
                        (cliente_id, consumo_atual_gb, media_30d_gb, stddev_gb, zscore, severidade)
                    SELECT %s, %s, %s, %s, %s, %s
                     WHERE NOT EXISTS (
                         SELECT 1 FROM consumo_anomalias
                          WHERE cliente_id = %s
                            AND ignorado = FALSE
                            AND detectado_em > NOW() - INTERVAL '7 days'
                     )
                    RETURNING id
                """, (
                    r["cliente_id"], r["atual_gb"], r["esperado_7d"],
                    r["sigma_7d"], zscore, severidade,
                    r["cliente_id"],
                ))
                inserted = cur.fetchone()
                if inserted:
                    detectadas.append({
                        "cliente_id": r["cliente_id"],
                        "nome": r["nome"],
                        "pppoe_login": r["pppoe_login"],
                        "atual_gb": float(r["atual_gb"]),
                        "esperado_gb": float(r["esperado_7d"]),
                        "zscore": zscore,
                        "severidade": severidade,
                    })
            conn.commit()
        conn.close()
    except Exception as e:
        log.warning("detect anomalies error: %s", e)
    return detectadas
