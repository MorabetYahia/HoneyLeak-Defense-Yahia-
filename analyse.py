"""
HoneyLeak Defense - analyse des alertes canary.
Lit hits.csv, geolocalise les IP externes et affiche les chiffres cles.
"""
import csv
import requests
from datetime import datetime, timezone

# Heure UTC exacte ou le depot appat a ete rendu public (a adapter)
LEAK_TIME = datetime(2026, 10, 27, 14, 45, 0, tzinfo=timezone.utc)


def load_hits(path="hits.csv"):
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def enrich(hits):
    for h in hits:
        source = h["source"].strip()
        if source[:1].isdigit():
            try:
                geo = requests.get(f"http://ip-api.com/json/{source}", timeout=5).json()
                h["pays"] = geo.get("country", "?")
                h["org"] = geo.get("org", "?")
            except Exception:
                h["pays"] = "?"
                h["org"] = "?"
        else:
            h["pays"] = "-"
            h["org"] = source
    return hits


def main():
    hits = enrich(load_hits())
    if not hits:
        print("Aucune alerte dans hits.csv")
        return

    first = min(hits, key=lambda h: h["timestamp"])
    first_dt = datetime.fromisoformat(first["timestamp"]).replace(tzinfo=timezone.utc)
    delta = (first_dt - LEAK_TIME).total_seconds()
    externes = [h for h in hits if h["type"].lower().startswith("bot")]

    print(f"Premier hit en {delta:.0f} secondes apres la fuite")
    print(f"Total alertes : {len(hits)}  |  Bots externes : {len(externes)}")
    print("-" * 70)
    for h in sorted(hits, key=lambda h: h["timestamp"]):
        print(f"{h['timestamp']} | {h['source']} | {h['pays']} | {h['event']}")


if __name__ == "__main__":
    main()
