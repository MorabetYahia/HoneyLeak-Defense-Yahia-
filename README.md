# HoneyLeak Defense

> A hands-on, defense-in-depth project against the bots that steal leaked secrets on GitHub.
> **Prevent** the leak, **trap** whatever slips through, and **analyze** whoever takes the bait.

Built on a normal Windows machine with free and open-source tools only — no virtual machines, no paid cloud.

---

## Table of contents

- [Why I built this](#why-i-built-this)
- [How it works — 3 layers](#how-it-works--3-layers)
- [Layer 1 — Prevention](#layer-1--prevention)
- [Layers 2 & 3 — Deception and analysis](#layers-2--3--deception-and-analysis)
- [An unexpected finding: GitHub already fights back](#an-unexpected-finding-github-already-fights-back)
- [Results](#results)
- [Reproduce it yourself](#reproduce-it-yourself)
- [What I learned (the hard parts)](#what-i-learned-the-hard-parts)
- [MITRE ATT&CK mapping](#mitre-attck-mapping)
- [Repository structure](#repository-structure)
- [Ethics & scope](#ethics--scope)

---

## Why I built this

If a developer accidentally commits an AWS key or an API token to a public repository, it doesn't stay unnoticed for long. Automated bots crawl GitHub around the clock looking for exactly that, and they can exploit a key within minutes.

A few numbers that convinced me the problem was worth a project:

- **29 million** new secrets were pushed to public GitHub in 2025 — up 34% in a year (GitGuardian).
- **543,699** still-valid credentials were found in public repositories in 2026 (Truffle Security).
- In one experiment, a leaked secret was found **and used in 127 seconds** (ThreatDown).

So I asked myself one question: *with open-source tools only, can I stop these leaks at the source, and catch the bots when a secret gets through anyway?*

---

## How it works — 3 layers

| Layer | Goal | Tool |
|-------|------|------|
| **1. Prevention** | Stop a secret before it ever reaches GitHub | Gitleaks (pre-commit + GitHub Actions) |
| **2. Deception** | Trap the bots with fake secrets | Canary tokens (Thinkst) |
| **3. Analysis** | Identify, profile and compare | Python + MITRE ATT&CK |

The first layer is the real defense. The other two are a safety net: if a secret ever escapes, I want to know about it instantly — and I want the attacker to waste their time on a useless key.

---

## Layer 1 — Prevention

The goal is simple: no secret should ever reach GitHub. I use the same scanner (Gitleaks) at two different moments.

First, I installed Gitleaks and checked it was working:

![Gitleaks installed and verified](images/03-gitleaks-version.png)

**Barrier 1 — on my machine (pre-commit).** A Git hook runs Gitleaks before every commit. If it spots a secret, the commit is refused before anything is even saved.

![Gitleaks detects and redacts the two secrets](images/04-precommit-blocked.png)

Here Gitleaks caught two secrets and redacted them, using two rules — `aws-access-token` for the key ID, and `generic-api-key` for the secret (entropy 4.81). The same scan runs as the pre-commit hook, so a commit containing a real key is refused before it's ever saved.

**Barrier 2 — on the server (GitHub Actions).** The same scan runs automatically on GitHub's servers at every push. This matters because the local hook can be bypassed (`git commit --no-verify`) or simply not installed by a teammate. The server-side check always runs.

![GitHub Actions secret scan passing](images/05-actions-green.png)

---

## Layers 2 & 3 — Deception and analysis

Prevention is never perfect, so I added tripwires — **canary tokens**: fake secrets that do nothing except raise an alert the moment someone tries to use them.

To make it a small experiment rather than a one-off test, I planted **several canary tokens of different types, in the file formats attackers scan most**, inside an innocent-looking public "backup scripts" repository. The question I wanted to answer: **which secret format do bots target first?**

### Bait inventory

| Bait file | Secret type | Why bots look here |
|-----------|-------------|--------------------|
| `credentials` | AWS key (canary) | Standard AWS CLI credentials file |
| `.env` | AWS key (canary) | The #1 place application secrets leak |
| `docker-compose.yml` | AWS key (canary) | Container environment variables |
| `backup.sql` | MySQL canary | Database dump (fires when the dump is executed) |

Each token carries a distinct label, so when an alert fires I know exactly which bait was taken.

![Canary token created on canarytokens.org](images/01-canary-setup.png)

Any time a key is used, I get an alert with the source IP, the timestamp, and the action attempted.

![Canary token triggered alert](images/06-canary-alert.png)

The `analyse.py` script reads `hits.csv` (one line per alert, tagged with its bait), geolocates external IPs via `ip-api.com`, and compares the baits — time to first hit and number of hits per bait.

---

## An unexpected finding: GitHub already fights back

When I tried to push a bait with a fake AWS key, GitHub's own **Push Protection** blocked me:

![GitHub Push Protection blocking the push](images/02-push-protection.png)

That was a lesson in itself. GitHub is a secret-scanning partner with AWS, so by default it refuses pushes that contain recognizable AWS keys. In other words, there's a defensive layer running before my own pipeline even enters the picture. I disabled it on the bait repository on purpose, for the experiment. Worth noting: even with Push Protection off, GitHub still forwards alerts to partners like AWS for secrets in public repos — which is exactly what triggered the AWS quarantine below. (Research also shows ~52% of real leaked secrets use formats this protection doesn't catch, so it helps but doesn't cover everything.)

---

## Results

The first trigger arrived **within about 2 minutes** of the first key going public. But reading it carefully taught me the most important lesson of the project — not every hit is an attacker.

| Timestamp (UTC) | Source | Event | Bait | What it really is |
|-----------------|--------|-------|------|-------------------|
| 2026-10-27 14:47 | AWS Internal | `AttachUserPolicy` | credentials | AWS auto-quarantining the leaked key |

This first "attacker" was actually **AWS itself**. When a key leaks publicly, AWS detects it and automatically attaches a quarantine policy to neutralize it (the `AttachUserPolicy` event). So my first hit was an automated *defense* system reacting in minutes — not a criminal bot.

Real malicious bots show up with **external IPs** and reconnaissance calls like `GetCallerIdentity` or `ListBuckets`. **As of this writing, no external bot has used the keys yet.** Four baits are live and being monitored, and I log every alert with the bait that fired, so I can compare them.

### Comparison (updated as data comes in)

| Bait | Secret type | First hit | Total hits |
|------|-------------|-----------|------------|
| credentials | AWS key | ~120 s (AWS auto-response) | 1 |
| .env | AWS key | — | 0 |
| docker-compose.yml | AWS key | — | 0 |
| backup.sql | MySQL | — | 0 |

> Early takeaway: a leaked AWS key is flagged by at least two automated systems (GitHub Push Protection, then AWS quarantine) within minutes — which is exactly why prevention at the source matters more than cleanup.

---

## Reproduce it yourself

**Layer 1 — prevention.** Add `.pre-commit-config.yaml` to your repo:

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1
    hooks:
      - id: gitleaks
```

Enable the hook, and add the GitHub Actions workflow in `.github/workflows/gitleaks.yml`:

```bash
pip install pre-commit
pre-commit install
```

```yaml
name: Secret scan
on: [push, pull_request]
jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Layers 2 & 3 — deception and analysis.** Create canary tokens at [canarytokens.org](https://canarytokens.org), plant each one in a public bait file, then log alerts into `hits.csv` and run:

```bash
pip install requests
python analyse.py
```

---

## What I learned (the hard parts)

A few things didn't work on the first try — and that's where I learned the most:

- **The AWS example key doesn't trigger anything.** My first test used `AKIAIOSFODNN7EXAMPLE` and nothing happened. Gitleaks keeps that key on an allowlist on purpose, because it's the placeholder from AWS's own documentation.
- **A fake key needs real randomness.** My next hand-made key also passed — its entropy was too low. Gitleaks only flags strings that look genuinely random. A real canary key (entropy ~3.8) was caught immediately.
- **Not all secrets carry the same risk.** An AWS key fires the instant a bot *uses* it, while a MySQL dump only fires when someone *executes* it against a server. Planting several bait types makes that difference measurable.
- **Telling defenders from attackers matters.** It would have been easy to log the first "AWS Internal" hit as a bot. Reading the event details carefully is the difference between real analysis and a wrong conclusion.

---

## MITRE ATT&CK mapping

| Technique | Where it appears in this project |
|-----------|----------------------------------|
| **T1552.001** — Unsecured Credentials: Credentials In Files | Secrets exposed in files in the repo |
| **T1593.003** — Search Open Websites/Domains: Code Repositories | Bots scanning GitHub for secrets |
| **T1078.004** — Valid Accounts: Cloud Accounts | Any attempt to use a stolen AWS key |

---

## Repository structure

```
honeyleak-defense/
├── .github/workflows/gitleaks.yml   # Layer 1 — server-side secret scan (CI)
├── .pre-commit-config.yaml          # Layer 1 — local secret scan (pre-commit)
├── analyse.py                       # Layer 3 — turns alerts into a comparative report
├── hits.csv                         # Layer 3 — log of canary alerts, tagged by bait
├── images/                          # Screenshots used in this README
└── README.md
```

The bait files themselves live in a separate, deliberately innocent-looking public repository, so the deception stays believable.

---

## Ethics & scope

This is a **100% defensive** project. Only canary tokens (fake secrets) are used — no real keys and no real AWS account are ever involved. The collected IPs are used strictly as indicators of compromise (IOCs) for analysis. I only observe the bots; I never scan, contact, or attack any of the IPs.

---

*Yahia Morabet — SOC / Threat Intelligence project, 2026 · [github.com/MorabetYahia](https://github.com/MorabetYahia)*
