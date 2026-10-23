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
// Dry run against the org list below (no changes made, just confirms it can find
// every rule row for every org):
//   node cascade_iac_severity.js --dry-run
//
// Real run:
//   node cascade_iac_severity.js
//
// Edit ORGS and RULES below before running for real. You need admin access on
// every org listed, under whichever account you authenticated as in --login.

const { chromium } = require('playwright');
const fs = require('fs');

const AUTH_FILE = 'auth.json';

// Org slugs to cascade the settings to (the part of the URL after /org/).
const ORGS = [
  'your-org-slug-1',
  'your-org-slug-2',
];

// Rule ID -> desired severity. Severity must be one of: critical, high, medium, low, none.
// Rule IDs are Snyk's public IaC rule catalog (see https://security.snyk.io/rules/cloud).
const RULES = {
  'SNYK-CC-AWS-419': 'none',
};

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

async function applyToOrg(context, orgSlug, dryRun) {
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
  for (const [ruleId, severity] of Object.entries(RULES)) {
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

  const dryRun = args.includes('--dry-run');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ storageState: AUTH_FILE });

  const summary = [];
  for (const orgSlug of ORGS) {
    summary.push(await applyToOrg(context, orgSlug, dryRun));
  }

  await browser.close();
  console.log('\n--- Summary ---');
  console.log(JSON.stringify(summary, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
