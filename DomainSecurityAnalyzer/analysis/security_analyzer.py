def assess_domain(item: dict, dns_data: dict) -> dict:
    """
    Punteggio euristico preliminare: misura indicatori di attenzione,
    non determina automaticamente che un dominio sia malevolo.
    """
    score = 0
    reasons = []

    similarity = item.get("similarity", 0)
    if similarity >= 90:
        score += 45
        reasons.append("Nome molto simile al dominio aziendale")
    elif similarity >= 75:
        score += 30
        reasons.append("Nome abbastanza simile al dominio aziendale")
    elif similarity >= 60:
        score += 15
        reasons.append("Nome parzialmente simile al dominio aziendale")

    if any(dns_data.get(record) for record in ("A", "AAAA")):
        score += 10
        reasons.append("Dominio con indirizzo IP risolto")

    if dns_data.get("MX"):
        score += 10
        reasons.append("Record MX presente")

    if not any(dns_data.get(record) for record in ("A", "AAAA", "CNAME")):
        reasons.append("Nessun record web risolto")

    score = min(score, 100)
    if score >= 60:
        level = "ALTO"
    elif score >= 30:
        level = "MEDIO"
    else:
        level = "BASSO"

    return {"risk_score": score, "risk_level": level, "reasons": reasons}
