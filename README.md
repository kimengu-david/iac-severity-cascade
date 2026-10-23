# IaC Severity Cascade

A small Playwright script for applying the same [Snyk IaC](https://docs.snyk.io/scan-with-snyk/snyk-infrastructure-as-code) rule-severity override to many orgs at once.

## The problem

Snyk's "Snyk IaC" org settings page (`app.snyk.io/org/<slug>/manage/cloud-config`) lets you override the severity of any IaC rule — including setting it to `None`, which removes that finding from scan results and pipeline gates. That's useful for silencing a rule that genuinely doesn't apply to your environment.

There's no public API for this setting. If you have the same override to apply across many orgs, the only documented way is to open each org's settings page and change it by hand, one rule, one org at a time.

## What this script does

It drives the actual settings page with a headless browser (Playwright) instead of a human: for each org in a list, it opens the page, finds the rule's dropdown, and selects the desired severity — the same action a person would take. The page itself saves each change immediately on selection, so there's no separate "submit" step to simulate.

This is browser automation of a real UI flow, not a reverse-engineered API client. If Snyk changes the page's markup, this will need updating.

## Setup

```bash
npm install
npx playwright install chromium
```

## Usage

**1. Log in once**, interactively, to capture a session:

```bash
node cascade_iac_severity.js --login
```

A real Chromium window opens. Log in via your normal SSO/GitHub/Google flow, then press Enter in the terminal once you're on `app.snyk.io` logged in. This saves a session to `auth.json` (gitignored — treat it like a password, never commit or share it).

**2. Set up your org and rule lists** — these are plain CSV files, not code, so editing a batch doesn't mean touching the script:

```bash
cp orgs.example.csv orgs.csv
cp rules.example.csv rules.csv
```

`orgs.csv` is one org slug per line (the part of the URL after `/org/`), under a `org_slug` header. You need admin access on every org listed, under whichever account you authenticated as. `rules.csv` maps a [Snyk IaC rule ID](https://security.snyk.io/rules/cloud) to a severity (`critical`, `high`, `medium`, `low`, or `none`), under an `rule_id,severity` header. Both files are gitignored, since a real list will contain your actual org slugs.

**3. Dry run** — confirms the script can find every rule on every org's settings page without changing anything:

```bash
node cascade_iac_severity.js --dry-run
```

**4. Run it for real:**

```bash
node cascade_iac_severity.js
```

Each org gets a per-rule `OK` / `FAILED` result printed live, plus a JSON summary at the end and a `results-<timestamp>.csv` audit trail (also gitignored) with one row per org/rule.

## Caveats

- This has only been exercised against orgs running **Current (classic) Snyk IaC**. Behavior under IaC+ is unverified.
- The session in `auth.json` has whatever access your logged-in account has. Treat it as a credential.
- If a rule can't be found on a given org's page, the script captures a screenshot and a text dump (`debug-<org>.png` / `.txt`, also gitignored) so you can see what actually rendered instead of guessing.
- Runs are sequential — budget roughly 10–15 seconds per org. For a large batch (dozens of orgs), that adds up; there's no concurrency yet (see below).

## Making it faster for a large batch

For a few dozen orgs or more, the sequential loop becomes the bottleneck well before the Snyk UI does. The straightforward next step is to process a handful of orgs concurrently (e.g. 5 at a time) using separate browser contexts sharing the same `auth.json` session, trading some speed for a higher chance of flaky, hard-to-debug failures under load. Not implemented here — worth adding only once a sequential run has proven the org/rule list is correct via `--dry-run`.
