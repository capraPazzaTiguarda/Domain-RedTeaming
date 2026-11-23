import re

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

def is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    try:
        domain.encode("ascii")
    except UnicodeEncodeError:
        # Per IDN, usare prima la conversione IDNA.
        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            return False

    labels = domain.split(".")
    if len(labels) < 2:
        return False
    return all(_LABEL.fullmatch(label) for label in labels)
