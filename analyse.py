"""
HoneyLeak Defense - analyse des hits capturs par les canary tokens.
Lit hits.csv (genere par parse_hits.py) et affiche le rapport de threat intel.

Usage : python analyse.py
"""
import csv
from collections import Counter

BEDROCK = {"InvokeModel", "InvokeModelWithResponseStream"}  # AWS Bedrock = LLMjacking


def load(path="hits.csv"):
    with open(path, encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def family(ua):
    return ua.lstrip("[").split("/")[0].strip()


def show(title, counter, n=12):
    print(title)
    for k, v in counter.most_common(n):
        print(f"  {v:>4}  {k}")
    print()


def main():
    rows = load()
    if not rows:
        print("hits.csv est vide. Lance d'abord parse_hits.py.")
        return
    rows.sort(key=lambda r: r["timestamp"])
    ips = {r["src_ip"] for r in rows}
    bedrock = [r for r in rows if r["event"] in BEDROCK]

    print("=" * 74)
    print("HONEYLEAK DEFENSE - RAPPORT DE THREAT INTELLIGENCE")
    print("=" * 74)
    print(f"Periode            : {rows[0]['timestamp']} -> {rows[-1]['timestamp']}")
    print(f"Requetes totales   : {len(rows)}")
    print(f"IP uniques         : {len(ips)}")
    print(f"Premiere exploit.  : {rows[0]['timestamp']} "
          f"({rows[0]['src_ip']}, {rows[0]['country']}, {rows[0]['event']})")
    print(f"LLMjacking (Bedrock): {len(bedrock)} tentatives")
    print("=" * 74)

    show("Pays d'origine :", Counter(r["country"] for r in rows))
    show("Type d'infrastructure :", Counter(r["asn_type"] for r in rows))
    show("Actions AWS tentees :", Counter(r["event"] for r in rows))
    show("Familles de bots (user-agent) :", Counter(family(r["useragent"]) for r in rows))
    show("Par leurre :", Counter(r["bait"] for r in rows))

    print("=" * 74)
    print("IP UNIQUES (1re apparition) :")
    seen = {}
    for r in rows:
        seen.setdefault(r["src_ip"], r)
    for ip, r in seen.items():
        print(f"  {r['timestamp']} | {ip:16} | {r['country']:3} | "
              f"{r['asn_type']:7} | {r['org'][:26]:26} | {r['event']}")


if __name__ == "__main__":
    main()
