"""
Validação do initData do Telegram WebApp.

Doc oficial:
https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app

Algoritmo:
1. Parse query string em pares chave=valor
2. Extrai 'hash' (assinatura)
3. Demais pares ordenados alfabeticamente, separados por '\\n'
4. secret_key = HMAC_SHA256("WebAppData", BOT_TOKEN)
5. expected = HMAC_SHA256(secret_key, data_check_string)
6. compara expected vs hash recebido (constant-time)
"""
import hmac
import hashlib
import json
import time
from urllib.parse import parse_qsl


# initData expira após 24h (auth_date é unix timestamp)
INIT_DATA_MAX_AGE = 24 * 3600


def validate_init_data(init_data_str: str, bot_token: str) -> dict | None:
    """
    Retorna dict com os campos parseados (incluindo 'user' como dict)
    se o initData for válido. Retorna None se inválido/expirado/forjado.
    """
    if not init_data_str or not bot_token:
        return None

    try:
        # parse_qsl preserva ordem; vamos converter para dict ordenado
        pairs = parse_qsl(init_data_str, keep_blank_values=True, strict_parsing=False)
    except Exception:
        return None

    parsed = dict(pairs)
    received_hash = parsed.pop("hash", None)
    if not received_hash:
        return None

    # auth_date guard contra replay attacks
    try:
        auth_date = int(parsed.get("auth_date", "0"))
    except ValueError:
        return None
    if auth_date <= 0 or (time.time() - auth_date) > INIT_DATA_MAX_AGE:
        return None

    data_check_string = "\n".join(f"{k}={parsed[k]}" for k in sorted(parsed.keys()))

    secret_key = hmac.new(
        b"WebAppData",
        bot_token.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    expected = hmac.new(
        secret_key,
        data_check_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, received_hash):
        return None

    # Decodifica 'user' se presente (vem como JSON string)
    if "user" in parsed:
        try:
            parsed["user"] = json.loads(parsed["user"])
        except Exception:
            pass

    return parsed


def get_authorized_user(get_db, telegram_user_id):
    """
    Verifica se o telegram_user_id está em mini_app_users e ativo.
    Atualiza ultimo_acesso. Retorna dict do usuário autorizado ou None.
    """
    if not telegram_user_id:
        return None
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT telegram_user_id, nome, role, ativo
                  FROM mini_app_users
                 WHERE telegram_user_id = %s AND ativo = TRUE
            """, (telegram_user_id,))
            row = cur.fetchone()
            if row:
                cur.execute(
                    "UPDATE mini_app_users SET ultimo_acesso=NOW() WHERE telegram_user_id=%s",
                    (telegram_user_id,),
                )
                conn.commit()
                return {
                    "telegram_user_id": row[0],
                    "nome": row[1],
                    "role": row[2],
                    "ativo": row[3],
                }
        conn.close()
    except Exception:
        return None
    return None
