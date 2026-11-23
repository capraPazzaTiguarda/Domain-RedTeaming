import csv

def export_csv(results: list[dict], destination: str) -> None:
    columns = [
        "domain", "similarity", "risk_score", "risk_level",
        "A", "AAAA", "MX", "NS", "CNAME", "reasons"
    ]
    with open(destination, "w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for item in results:
            row = dict(item)
            row["reasons"] = "; ".join(row.get("reasons", []))
            for key in ("A", "AAAA", "MX", "NS", "CNAME"):
                row[key] = "; ".join(row.get(key, []))
            writer.writerow(row)
