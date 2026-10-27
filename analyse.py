"""
HoneyLeak Defense - analyse comparative des alertes canary.
Lit hits.csv, geolocalise les IP externes, et compare les leurres entre eux.
"""
import csv
import requests
from collections import defaultdict
from datetime import datetime, timezone

# Heure UTC exacte ou le premier depot appat a ete rendu public (a adapter)
LEAK_TIME = datetime(2026, 10, 27, 14, 45, 0, tzinfo=timezone.utc)


def load_hits(path="hits.csv"):
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def enrich(hits):
    for h in hits:
        source = h["source"].strip()
        if source[:1].isdigit():  # c'est une IP -> on geolocalise
            try:
                geo = requests.get(f"http://ip-api.com/json/{source}", timeout=5).json()
                h["pays"] = geo.get("country", "?")
                h["org"] = geo.get("org", "?")
            except Exception:
                h["pays"] = "?"
                h["org"] = "?"
        else:  # source non-IP (ex. "AWS Internal")
            h["pays"] = "-"
            h["org"] = source
    return hits


def seconds_since_leak(ts):
    return (datetime.fromisoformat(ts).replace(tzinfo=timezone.utc) - LEAK_TIME).total_seconds()


def main():
    hits = enrich(load_hits())
    if not hits:
        print("Aucune alerte dans hits.csv")
        return

    hits.sort(key=lambda h: h["timestamp"])
    externes = [h for h in hits if h["type"].lower().startswith("bot")]

    print(f"Premier hit en {seconds_since_leak(hits[0]['timestamp']):.0f} s")
    print(f"Total alertes : {len(hits)}  |  Bots externes : {len(externes)}")
    print("=" * 72)

    # Comparaison par leurre
    by_bait = defaultdict(list)
    for h in hits:
        by_bait[h.get("bait", "?")].append(h)

    print("Comparaison par leurre :")
    print(f"  {'Leurre':22} | {'Hits':>4} | 1er hit")
    print("  " + "-" * 44)
    for bait, rows in sorted(by_bait.items()):
        t0 = seconds_since_leak(rows[0]["timestamp"])
        print(f"  {bait:22} | {len(rows):>4} | {t0:.0f} s")
    print("=" * 72)

    # Detail chronologique
    for h in hits:
        print(f"{h['timestamp']} | {h['source']:16} | {h['pays']:12} | {h['event']:18} | {h.get('bait','')}")


if __name__ == "__main__":
    main()
