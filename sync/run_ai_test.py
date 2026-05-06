"""
Diagnóstico do provider de IA.
Uso: docker exec radius_sync python run_ai_test.py
"""
import logging
import os

# Habilita logs WARNING pra ver erros HTTP
logging.basicConfig(level=logging.WARNING, format='[%(name)s %(levelname)s] %(message)s')

from ai_summary import _detect_provider, _call_llm


def main():
    print("=" * 60)
    print("DIAGNÓSTICO IA")
    print("=" * 60)

    # Mostra todas as env vars de provider (mascaradas)
    keys = ["AI_PROVIDER", "AI_MODEL", "GITHUB_TOKEN", "CF_AI_TOKEN",
            "CF_ACCOUNT_ID", "GROQ_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"]
    print("\nEnv vars setadas:")
    for k in keys:
        v = os.environ.get(k, "")
        if v:
            mask = v[:6] + "..." + v[-4:] if len(v) > 12 else "(curto demais)"
            print(f"  {k:20s} = {mask}")
        else:
            print(f"  {k:20s} = (vazio)")

    print("\n" + "-" * 60)

    provider, cfg = _detect_provider()
    print(f"\nProvider detectado: {provider}")
    if cfg:
        print(f"URL:    {cfg.get('url')}")
        print(f"Modelo: {cfg.get('model')}")
        key = cfg.get("key", "")
        print(f"Key:    {key[:6]}...{key[-4:]} ({len(key)} chars)")
    else:
        print("Nenhum provider configurado.")
        return

    print("\n" + "-" * 60)
    print("\nFazendo chamada de teste...")
    resposta = _call_llm(
        "Você responde em português, em uma frase curta.",
        "Diga apenas: teste OK",
        max_tokens=50,
    )

    print("\n" + "=" * 60)
    if resposta:
        print("RESULTADO: ✓ FUNCIONA")
        print(f"Resposta: {resposta}")
    else:
        print("RESULTADO: ✗ FALHOU")
        print("Veja os logs WARNING acima pra detalhe do erro HTTP.")
    print("=" * 60)


if __name__ == "__main__":
    main()
