// Cascade Snyk IaC rule severity overrides across many orgs via browser automation.
//
// Why this exists: there is no public API for the Org-level "Snyk IaC" severity
// settings page (app.snyk.io/org/<slug>/manage/cloud-config). Each rule's <select>
// fires a request to an internal endpoint as soon as you change it — there is no
// separate "Save" step. This script drives that same UI interaction headlessly,
// one org at a time, using Playwright, so the same override doesn't have to be
// clicked through by hand on every org.
//
// Setup:
//   npm install
//   npx playwright install chromium
//
// First run (captures your login session so later runs don't need to re-auth):
//   node cascade_iac_severity.js --login
//   (a browser window opens; log in via SSO/GitHub/Google, then press Enter in the
//   terminal once you land on app.snyk.io logged in. Session is saved to auth.json,
//   which is gitignored — never commit it, it's equivalent to your login session.)
//
// Org and rule lists live in plain CSV files, not in this code — copy the
// .example.csv files and edit those:
//   cp orgs.example.csv orgs.csv
//   cp rules.example.csv rules.csv
//
// Dry run (no changes made, just confirms it can find every rule row for every org):
//   node cascade_iac_severity.js --dry-run
//
// Real run:
//   node cascade_iac_severity.js
//   Writes a results-<timestamp>.csv with one row per org/rule for an audit trail.
//
// You need admin access on every org listed, under whichever account you
// authenticated as in --login.

const { chromium } = require('playwright');
const fs = require('fs');

const AUTH_FILE = 'auth.json';
const ORGS_FILE = 'orgs.csv';
const RULES_FILE = 'rules.csv';

const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'none']);

// Reads a single-column CSV (header "org_slug", one slug per row after that).
function readOrgsCsv(path) {
  const lines = fs.readFileSync(path, 'utf8').split('\n').map((l) => l.trim()).filter(Boolean);
  const [, ...rows] = lines; // drop header
  return rows;
}

// Reads a two-column CSV (header "rule_id,severity").
function readRulesCsv(path) {
  const lines = fs.readFileSync(path, 'utf8').split('\n').map((l) => l.trim()).filter(Boolean);
  const [, ...rows] = lines; // drop header
  const rules = {};
  for (const row of rows) {
    const [ruleId, severity] = row.split(',').map((s) => s.trim());
    if (!ruleId || !severity) continue;
    if (!VALID_SEVERITIES.has(severity)) {
      throw new Error(`Invalid severity "${severity}" for rule ${ruleId} in ${path}. Must be one of: ${[...VALID_SEVERITIES].join(', ')}`);
    }
    rules[ruleId] = severity;
  }
  return rules;
}

function writeResultsCsv(summary) {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const path = `results-${timestamp}.csv`;
  const rows = ['org_slug,rule_id,status,http_status'];
  for (const { orgSlug, results } of summary) {
    if (results.length === 0) {
      rows.push(`${orgSlug},,page_load_failed,`);
      continue;
    }
    for (const r of results) {
      rows.push(`${orgSlug},${r.ruleId},${r.status},${r.httpStatus ?? ''}`);
    }
  }
  fs.writeFileSync(path, rows.join('\n') + '\n');
  return path;
}

async function captureLogin() {
  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto('https://app.snyk.io/login');
  console.log('Log in in the opened browser window, then press Enter here once you are logged in...');
  await new Promise((resolve) => process.stdin.once('data', resolve));
  await context.storageState({ path: AUTH_FILE });
  await browser.close();
  console.log(`Saved session to ${AUTH_FILE}`);
}

async function applyToOrg(context, orgSlug, rules, dryRun) {
  const page = await context.newPage();
  await page.goto(`https://app.snyk.io/org/${orgSlug}/manage/cloud-config`, {
    waitUntil: 'networkidle',
  });

  // Target the iframe by element, not by URL: the outer page's own URL also
  // contains "/manage/cloud-config", so matching frames by URL substring
  // grabs the main frame instead of the nested iframe that actually holds
  // the rule table.
  const frame = page.frameLocator('iframe[id^="iFrameResizer"]');

  // The iframe's app renders the rule table asynchronously after the iframe
  // itself finishes loading — page-level networkidle doesn't wait for that.
  // Wait for at least one severity <select> to actually mount before
  // querying for specific rules, or every lookup below will report "not found".
  try {
    await frame.locator('select[id$="Severity"]').first().waitFor({ timeout: 15000 });
  } catch {
    console.error(`[${orgSlug}] rule table never rendered — skipping`);
    const debugPrefix = `debug-${orgSlug.replace(/[^a-z0-9.-]/gi, '_')}`;
    try {
      await page.screenshot({ path: `${debugPrefix}.png`, fullPage: true });
      const bodyText = await frame.locator('body').innerText();
      fs.writeFileSync(`${debugPrefix}.txt`, `page.url(): ${page.url()}\n\n${bodyText.slice(0, 2000)}`);
      console.error(`[${orgSlug}] wrote ${debugPrefix}.png and ${debugPrefix}.txt for inspection`);
    } catch (debugErr) {
      console.error(`[${orgSlug}] debug capture also failed: ${debugErr.message}`);
    }
    await page.close();
    return { orgSlug, results: [] };
  }

  const results = [];
  for (const [ruleId, severity] of Object.entries(rules)) {
    const locator = frame.locator(`select[id="${ruleId}Severity"]`);
    const count = await locator.count();
    if (count === 0) {
      console.warn(`[${orgSlug}] rule ${ruleId} not found on this org's settings page`);
      results.push({ ruleId, status: 'not_found' });
      continue;
    }

    if (dryRun) {
      console.log(`[${orgSlug}] DRY RUN: would set ${ruleId} -> ${severity}`);
      results.push({ ruleId, status: 'dry_run' });
      continue;
    }

    const [response] = await Promise.all([
      page.waitForResponse(
        (r) => r.url().includes('updateCloudConfigSetting') && r.request().method() === 'PUT',
        { timeout: 10000 }
      ),
      locator.selectOption(severity),
    ]);

    const ok = response.ok();
    console.log(`[${orgSlug}] ${ruleId} -> ${severity}: ${ok ? 'OK' : `FAILED (${response.status()})`}`);
    results.push({ ruleId, status: ok ? 'ok' : 'failed', httpStatus: response.status() });
  }

  await page.close();
  return { orgSlug, results };
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--login')) {
    await captureLogin();
    return;
  }

  if (!fs.existsSync(AUTH_FILE)) {
    console.error(`No ${AUTH_FILE} found. Run with --login first.`);
    process.exit(1);
  }

  for (const [file, example] of [[ORGS_FILE, 'orgs.example.csv'], [RULES_FILE, 'rules.example.csv']]) {
    if (!fs.existsSync(file)) {
      console.error(`No ${file} found. Copy ${example} to ${file} and edit it first.`);
      process.exit(1);
    }
  }

  const orgs = readOrgsCsv(ORGS_FILE);
  const rules = readRulesCsv(RULES_FILE);
  console.log(`Loaded ${orgs.length} org(s) from ${ORGS_FILE} and ${Object.keys(rules).length} rule(s) from ${RULES_FILE}.`);

  const dryRun = args.includes('--dry-run');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ storageState: AUTH_FILE });

  const summary = [];
  for (const orgSlug of orgs) {
    summary.push(await applyToOrg(context, orgSlug, rules, dryRun));
  }

  await browser.close();
  console.log('\n--- Summary ---');
  console.log(JSON.stringify(summary, null, 2));

  if (!dryRun) {
    const resultsPath = writeResultsCsv(summary);
    console.log(`\nWrote audit trail to ${resultsPath}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
