import dns.resolver

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "CNAME")

def resolve_domain(domain: str) -> dict:
    result = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4
    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type)
            result[record_type] = [answer.to_text() for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            result[record_type] = []
        except Exception:
            result[record_type] = []
    return result
