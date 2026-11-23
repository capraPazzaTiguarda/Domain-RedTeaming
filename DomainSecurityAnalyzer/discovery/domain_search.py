from rapidfuzz.fuzz import ratio
from config import SIMILARITY_THRESHOLD

def registered_domain(hostname: str) -> str:
    """Restituisce il dominio registrabile usando la Public Suffix List."""
    import tldextract
    ext = tldextract.TLDExtract(suffix_list_urls=())(hostname)
    if not ext.domain or not ext.suffix:
        return hostname
    return f"{ext.domain}.{ext.suffix}"

def find_similar_domains(target: str, candidates: list[str]) -> list[dict]:
    target_root = registered_domain(target)
    target_label = target_root.rsplit(".", 1)[0]
    found = []

    for hostname in candidates:
        root = registered_domain(hostname)
        if root == target_root:
            continue
        label = root.rsplit(".", 1)[0]
        score = round(ratio(target_label, label))
        if score >= SIMILARITY_THRESHOLD:
            found.append({
                "domain": root,
                "similarity": score,
                "source_host": hostname
            })

    # Elimina duplicati mantenendo il punteggio più alto.
    unique = {}
    for item in found:
        old = unique.get(item["domain"])
        if old is None or item["similarity"] > old["similarity"]:
            unique[item["domain"]] = item

    return sorted(unique.values(), key=lambda x: x["similarity"], reverse=True)
