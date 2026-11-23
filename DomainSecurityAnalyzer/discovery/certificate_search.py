import requests
from config import REQUEST_TIMEOUT, MAX_CANDIDATES

CRT_SH_URL = "https://crt.sh/"

def search_certificate_domains(domain: str) -> list[str]:
    """
    Cerca su crt.sh i nomi DNS comparsi nei certificati pubblici.
    Il wildcard cerca il dominio e i suoi sottodomini; non è una ricerca
    universale di domini typosquatting.
    """
    response = requests.get(
        CRT_SH_URL,
        params={"q": f"%.{domain}", "output": "json"},
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": "DomainSecurityAnalyzer/1.0"}
    )
    response.raise_for_status()

    try:
        records = response.json()
    except ValueError:
        return []

    names = set()
    for record in records[:MAX_CANDIDATES * 5]:
        value = record.get("name_value", "")
        for name in value.splitlines():
            name = name.strip().lower().lstrip("*.")
            if name and name.endswith("." + domain):
                names.add(name)

    return sorted(names)[:MAX_CANDIDATES]
