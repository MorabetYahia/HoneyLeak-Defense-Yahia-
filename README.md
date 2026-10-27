# HoneyLeak Defense

A hands-on, defense-in-depth project against the bots that steal leaked secrets on GitHub. The idea is simple: **prevent** the leak, **trap** whatever slips through, and **analyze** whoever takes the bait.

I built this on my own machine in a single day, with free and open-source tools only. No virtual machines, no paid cloud.

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
| **2. Deception** | Trap the bots with a fake secret | Canary token (Thinkst) |
| **3. Analysis** | Identify and profile the attacker | Python + MITRE ATT&CK |

The first layer is the real defense. The other two are a safety net: if a secret ever escapes, I want to know about it instantly — and I want the attacker to waste their time on a useless key.

---

## Layer 1 — Prevention

Two barriers, using the same scanner (Gitleaks) at two different moments.

First, I installed Gitleaks and checked it was working:

![Gitleaks installed and verified](images/03-gitleaks-version.png)

**Barrier 1 — on my machine (pre-commit).** A Git hook runs Gitleaks before every commit. If it spots a secret, the commit is refused before anything is even saved.

![Gitleaks detects and redacts the two secrets](images/04-precommit-blocked.png)

Here Gitleaks found two secrets and redacted them (notice the entropy values — more on that below). The same scan runs as the pre-commit hook, so a commit containing a real key is refused before it's ever saved.

**Barrier 2 — on the server (GitHub Actions).** The same scan runs automatically on GitHub's servers at every push. This matters because the local hook can be bypassed (`git commit --no-verify`) or simply not installed by a teammate. The server-side check always runs.

![GitHub Actions secret scan passing](images/05-actions-green.png)

---

## Layers 2 & 3 — Deception and analysis

I created a **canary token** (a fake AWS key that does nothing except raise an alert the moment someone uses it) and planted it in a separate, innocent-looking public "backup scripts" repository.

![Canary token created on canarytokens.org](images/01-canary-setup.png)

Then I made the repo public and started the clock. Any time the key is used, I get an alert with the source IP, the time, and the AWS action that was attempted.

![Canary token triggered alert](images/06-canary-alert.png)

A small Python script turns these raw alerts into an analyst-style report. It reads a `hits.csv` file (one line per alert), geolocates each IP, and prints the key numbers: time to first access, number of attempts, and the countries / hosting providers involved.

---

## An unexpected finding: GitHub already fights back

When I tried to push my bait repo with the fake key, GitHub's own **Push Protection** blocked me:

![GitHub Push Protection blocking the push](images/02-push-protection.png)

That was a lesson in itself. GitHub is a secret-scanning partner with AWS, so it refuses pushes containing recognizable AWS keys by default. In other words, there's a defensive layer running before my own pipeline even enters the picture. (Worth noting: research shows ~52% of real leaked secrets use formats this protection doesn't catch — so it helps, but doesn't cover everything.) I allowed the secret on purpose, for the experiment, and the push went through.

---

## Results

The very first trigger arrived **within about 1–3 minutes** of the key going public. But reading it carefully taught me something important:

- **Source IP: AWS Internal**
- **Event: AttachUserPolicy**

This first hit wasn't a criminal bot — it was **AWS itself**. When a key leaks publicly, AWS automatically attaches a quarantine policy to neutralize it (that's the `AttachUserPolicy` event). So my first "attacker" was actually an automated *defense* system reacting in minutes.

The malicious bots are the ones that show up with **external IPs** and reconnaissance calls like `GetCallerIdentity` or `ListBuckets`. I keep logging every alert and separating the two categories: automated AWS responses on one side, external bots on the other.

*(This section is updated as new alerts come in.)*

---

## What I learned (the hard parts)

A few things didn't work on the first try — and that's where I learned the most:

- **The AWS example key doesn't trigger anything.** My first test used `AKIAIOSFODNN7EXAMPLE` and nothing happened. It turns out Gitleaks keeps that key on an allowlist on purpose, because it's the placeholder from AWS's own documentation.
- **A fake key needs real randomness.** My next hand-made key also passed — its entropy was too low. Gitleaks only flags strings that look genuinely random. A real canary key (entropy ~3.8) was caught immediately by the `aws-access-token` rule.
- **Telling defenders from attackers matters.** It would have been easy to log the first "AWS Internal" hit as a bot. Reading the event details carefully is the difference between a real analysis and a wrong conclusion.

---

## MITRE ATT&CK mapping

- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1593.003** — Search Open Websites/Domains: Code Repositories
- **T1078.004** — Valid Accounts: Cloud Accounts

---

## Tech stack

Gitleaks · pre-commit · GitHub Actions · Canary tokens (Thinkst) · Python · MITRE ATT&CK

---

## Ethics & scope

This is a **100% defensive** project. Only canary tokens (fake secrets) are used — no real keys and no real AWS account are ever involved. The collected IPs are used strictly as indicators of compromise (IOCs) for analysis. I only observe the bots; I never scan, contact, or attack any of the IPs.

---

*Yahia Morabet — SOC / Threat Intelligence project, 2026*
