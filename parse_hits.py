"""
HoneyLeak Defense - parseur des exports Canarytokens.
Lit tous les CSV exportes depuis canarytokens.org (dossier ./canary_raw/)
et produit un hits.csv propre et consolide.

Usage : python parse_hits.py
"""
import csv
import re
import glob

RAW_DIR = "canary_raw"      # dossier contenant les exports bruts Canarytokens
OUT = "hits.csv"

# Associe chaque compte AWS canary (accountId) au fichier appat correspondant.
# Complete avec tes memos (regarde dans canarytokens.org quel memo = quel accountId).
BAIT = {
    "679513306728": "bait-A",
    "874244580194": "bait-B",
}


def clean(v):
    v = (v or "").strip()
    return v[1:] if v.startswith("'") else v


def grab(pattern, text):
    m = re.search(pattern, text)
    return m.group(1) if m else ""


def parse_file(path, rows):
    with open(path, encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            if not r.get("Timestamp"):
                continue
            geo = clean(r.get("geo_info"))
            add = clean(r.get("additional_info"))
            account = grab(r"'accountId': \['([^']*)'\]", add)
            rows.append({
                "timestamp": clean(r["Timestamp"]).split(".")[0],
                "src_ip": clean(r.get("src_ip")),
                "country": grab(r"country='([^']*)'", geo),
                "city": grab(r"city='([^']*)'", geo),
                "org": grab(r"name='([^']*)'", geo),
                "asn_type": grab(r"type='([^']*)'", geo),
                "useragent": clean(r.get("useragent")),
                "event": grab(r"'eventName': \['([^']*)'\]", add),
                "account": account,
                "bait": BAIT.get(account, account),
            })


def main():
    rows = []
    files = sorted(glob.glob(f"{RAW_DIR}/*.csv"))
    if not files:
        print(f"Aucun export trouve dans {RAW_DIR}/")
        return
    for path in files:
        parse_file(path, rows)

    # tri chronologique + dedup exact (meme ip + event + timestamp)
    rows.sort(key=lambda x: x["timestamp"])
    seen, clean_rows = set(), []
    for r in rows:
        key = (r["timestamp"], r["src_ip"], r["event"])
        if key in seen:
            continue
        seen.add(key)
        clean_rows.append(r)

    cols = ["timestamp", "src_ip", "country", "city", "org",
            "asn_type", "useragent", "event", "account", "bait"]
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(clean_rows)

    print(f"{len(files)} exports lus -> {len(clean_rows)} lignes ecrites dans {OUT}")


if __name__ == "__main__":
    main()
