def normalize_domain(value: str) -> str:
    """Normalizza un dominio inserito dall'utente."""
    value = value.strip().lower()

    # Consente di incollare anche un URL completo.
    for prefix in ("https://", "http://"):
        if value.startswith(prefix):
            value = value[len(prefix):]
            break

    value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    value = value.split(":", 1)[0]  # rimuove una porta semplice
    return value.rstrip(".")
