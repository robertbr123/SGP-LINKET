"""
Predição de falhas em CPE via regressão linear sobre histórico Rx Power.

Critério para alertar:
- CPE tem >= N pontos em <= 7 dias
- slope (dB/dia) é negativo
- R² >= 0.5 (tendência consistente, não ruído)
- projeção atinge -27 dBm em <= 14 dias
- ainda NÃO está abaixo de -27 (senão é o alerta normal)

Roda 1x por dia (chamado pelo summaries.py junto com o resumo matinal).
"""
import logging
import psycopg2.extras

log = logging.getLogger("predictions")


def _linear_regression(xs, ys):
    """
    Retorna (slope, intercept, r_squared). xs e ys devem ter mesmo tamanho.
    Implementação manual para evitar dependência de numpy.
    """
    n = len(xs)
    if n < 3:
        return 0.0, 0.0, 0.0
    sum_x = sum(xs)
    sum_y = sum(ys)
    sum_xy = sum(x * y for x, y in zip(xs, ys))
    sum_x2 = sum(x * x for x in xs)
    sum_y2 = sum(y * y for y in ys)

    denom = (n * sum_x2 - sum_x * sum_x)
    if denom == 0:
        return 0.0, sum_y / n, 0.0

    slope = (n * sum_xy - sum_x * sum_y) / denom
    intercept = (sum_y - slope * sum_x) / n

    # R²
    y_mean = sum_y / n
    ss_tot = sum((y - y_mean) ** 2 for y in ys)
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    r2 = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0.0
    return slope, intercept, r2


def _get_cfg(conn, chave, default=""):
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT valor FROM alertas_config WHERE chave=%s", (chave,))
            row = cur.fetchone()
            return row[0] if row else default
    except Exception:
        return default


def check_cpe_predictions(conn, redis_client, notifier):
    """Analisa todos os CPEs com histórico recente e prediz falhas."""
    rx_min = float(_get_cfg(conn, "rx_power_min", "-27"))

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Quais CPEs têm histórico nos últimos 7 dias?
            cur.execute("""
                SELECT cpe.id, cpe.modelo, cpe.fabricante, cpe.rx_power,
                       c.nome AS cliente_nome, c.pppoe_login
                  FROM cpe_devices cpe
                  LEFT JOIN clientes c ON c.id = cpe.cliente_id
                 WHERE cpe.online = TRUE
                   AND cpe.id IN (
                     SELECT cpe_id FROM cpe_rx_history
                      WHERE criado_em > NOW() - INTERVAL '7 days'
                      GROUP BY cpe_id HAVING COUNT(*) >= 10
                   )
            """)
            cpes = cur.fetchall()
    except psycopg2.errors.UndefinedTable:
        log.info("cpe_rx_history ainda não existe — pulando predições")
        return
    except Exception as e:
        log.warning("predictions query error: %s", e)
        return

    log.info("predictions: analisando %d CPE(s) com histórico", len(cpes))

    for cpe in cpes:
        cpe_id = cpe["id"]

        # Já está abaixo do limiar? Não predizer (já existe alerta de Rx crítico)
        if cpe["rx_power"] is not None and cpe["rx_power"] < rx_min:
            continue

        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT EXTRACT(EPOCH FROM (NOW() - criado_em)) / 86400 AS dias_atras,
                           rx_power
                      FROM cpe_rx_history
                     WHERE cpe_id = %s
                       AND criado_em > NOW() - INTERVAL '7 days'
                  ORDER BY criado_em
                """, (cpe_id,))
                rows = cur.fetchall()
        except Exception:
            continue

        if len(rows) < 10:
            continue

        # x = -dias_atras (mais antigo = negativo, mais novo = ~0)
        # y = rx_power
        xs = [-float(r["dias_atras"]) for r in rows]
        ys = [float(r["rx_power"]) for r in rows]

        slope, intercept, r2 = _linear_regression(xs, ys)

        # Projeção: quando rx_power(t) = rx_min?
        # rx = slope * t + intercept  →  t = (rx_min - intercept) / slope
        # Se slope >= -0.1 dB/dia (degradação muito lenta), ignora
        if slope >= -0.1:
            continue
        if r2 < 0.5:
            continue  # tendência muito ruidosa pra confiar

        # Quando vai cruzar?
        try:
            t_critico = (rx_min - intercept) / slope
        except ZeroDivisionError:
            continue
        # t_critico está em "dias a partir do mais antigo" — converto pra dias_a_partir_de_hoje
        # x atual é ~0 (mais novo). t_critico negativo seria no passado, positivo no futuro.
        dias_ate_falha = t_critico - max(xs)  # max(xs) ~ 0

        if dias_ate_falha < 0 or dias_ate_falha > 14:
            continue  # ou já está abaixo, ou muito longe pra alertar

        rx_atual = cpe["rx_power"] or ys[-1]
        nome = cpe["cliente_nome"] or cpe["pppoe_login"] or f"CPE #{cpe_id}"
        msg = (
            f"<b>📉 CPE com sinal degradando</b>\n"
            f"Cliente: {nome}\n"
            f"Modelo: {cpe.get('fabricante') or ''} {cpe.get('modelo') or ''}\n"
            f"Rx atual: {rx_atual:.1f} dBm (limiar: {rx_min:.0f})\n"
            f"Taxa de queda: {slope:.2f} dB/dia (R² = {r2:.2f})\n"
            f"<b>Previsão de falha em ~{dias_ate_falha:.0f} dia(s)</b>\n"
            f"<i>Atue antes do cliente perceber: limpe conector, "
            f"verifique fusão, considere troca de pigtail.</i>"
        )

        notifier.fire(
            f"cpe_degradando:{cpe_id}",
            msg,
            severity="warning",
            cooldown=86400,  # uma vez por dia por CPE
        )
        log.info("predição CPE #%d: %.1f dias até falha (slope=%.2f, R²=%.2f)",
                 cpe_id, dias_ate_falha, slope, r2)


def cleanup_old_rx_history(conn, days=30):
    """Mantém só os últimos N dias de histórico."""
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM cpe_rx_history WHERE criado_em < NOW() - (%s * INTERVAL '1 day')",
                (days,),
            )
            n = cur.rowcount
        conn.commit()
        if n > 0:
            log.info("cpe_rx_history: %d linhas antigas removidas", n)
    except Exception as e:
        log.warning("cleanup_old_rx_history error: %s", e)
