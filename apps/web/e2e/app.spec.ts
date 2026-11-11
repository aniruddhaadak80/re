import { test, expect, type Page } from '@playwright/test';
import { existsSync, mkdirSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..', '..', '..');
const samples = join(repo, 'samples');
const shots = join(here, 'screenshots');
mkdirSync(shots, { recursive: true });

const mdSlugs = (dir: string) => (existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith('.md')).map((f) => f.replace(/\.md$/, '')) : []);
const docSlugs = mdSlugs(join(repo, 'docs'));
const postSlugs = mdSlugs(join(repo, 'content', 'blog'));

const ROUTES = ['', 'analyze', 'diff', 'verify', 'docs', 'blog', 'about', 'changelog', 'settings', 'this-page-does-not-exist',
  ...docSlugs.map((s) => `docs/${s}`), ...postSlugs.map((s) => `blog/${s}`)];

/** Collects console errors and page errors for a test. */
function watch(page: Page): string[] {
  const errors: string[] = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(`console: ${m.text()}`); });
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  return errors;
}

async function upload(page: Page, file: string) {
  await page.goto('analyze');
  await page.getByTestId('file-input').setInputFiles(join(samples, file));
  await expect(page.getByTestId('tab-overview')).toBeVisible({ timeout: 30_000 });
}

async function setTheme(page: Page, theme: 'black' | 'dark' | 'sun' | 'system') {
  await page.evaluate((t) => localStorage.setItem('revlens.settings', JSON.stringify({ theme: t, accent: 'gold', motion: 'reduced' })), theme);
}

test.describe('routes', () => {
  for (const r of ROUTES) {
    test(`/${r} renders a heading without console errors`, async ({ page }) => {
      const errors = watch(page);
      const res = await page.goto(r);
      expect(res?.status()).toBeLessThan(400);
      await expect(page.locator('h1').first()).toBeVisible();
      await expect(page.locator('h1').first()).not.toBeEmpty();
      await page.waitForTimeout(r.startsWith('docs') || r.startsWith('blog') ? 1500 : 300);
      expect(errors).toEqual([]);
    });
  }

  test('built output has a page per route, a 404 page, sitemap and robots', async () => {
    const dist = join(here, '..', 'dist');
    for (const r of ['analyze', 'diff', 'verify', 'docs', 'blog', 'about', 'changelog', 'settings', ...docSlugs.map((s) => `docs/${s}`), ...postSlugs.map((s) => `blog/${s}`)]) {
      expect(existsSync(join(dist, r, 'index.html')), `${r}/index.html`).toBe(true);
    }
    expect(existsSync(join(dist, '404.html'))).toBe(true);
    expect(readFileSync(join(dist, 'sitemap.xml'), 'utf8')).toContain('https://aniruddhaadak80.github.io/re/analyze/');
    expect(readFileSync(join(dist, 'robots.txt'), 'utf8')).toContain('Sitemap:');
    expect(readFileSync(join(dist, 'analyze', 'index.html'), 'utf8')).toContain('<title>Analyze a file | RevLens</title>');
    expect(existsSync(join(dist, 'manifest.webmanifest'))).toBe(true);
    expect(existsSync(join(dist, 'sw.js'))).toBe(true);
    expect(existsSync(join(dist, 'og.png'))).toBe(true);
  });
});

test.describe('analyze real samples', () => {
  test('react-dom bundle shows react-dom 18.3.1', async ({ page }) => {
    const errors = watch(page);
    await upload(page, 'react-dom.production.min.js');
    await expect(page.getByTestId('file-format')).toHaveText('JavaScript');
    await page.getByTestId('tab-components').click();
    const row = page.getByTestId('component-row').filter({ hasText: 'react-dom' });
    await expect(row).toContainText('18.3.1');
    await expect(row).toContainText('pkg:npm/react-dom@18.3.1');
    expect(errors).toEqual([]);
  });

  test('ls ELF shows format, sections, imports and hex', async ({ page }) => {
    const errors = watch(page);
    await upload(page, 'ls-linux.elf');
    await expect(page.getByTestId('file-format')).toHaveText('ELF');
    await expect(page.getByTestId('timings')).toBeVisible();
    await page.getByTestId('tab-sections').click();
    const table = page.getByTestId('sections-table');
    await expect(table).toContainText('.text');
    expect(await table.locator('tbody tr').count()).toBeGreaterThan(10);
    await page.getByTestId('tab-imports').click();
    await expect(page.getByText(/libc\.so/).first()).toBeVisible();
    await page.getByTestId('tab-entropy').click();
    await expect(page.getByTestId('entropy-chart')).toBeVisible();
    await page.getByTestId('entropy-bar').nth(3).hover();
    await expect(page.getByTestId('entropy-tooltip')).toContainText('Entropy');
    await page.getByTestId('entropy-bar').first().click();
    await expect(page.getByTestId('hex-view')).toBeVisible();
    await expect(page.getByTestId('hex-view')).toContainText('7F454C46');
    await expect(page.getByTestId('hex-selection')).toContainText('0x000000');
    expect(errors).toEqual([]);
  });

  test('left-pad tarball shows left-pad 1.3.0 and its members', async ({ page }) => {
    const errors = watch(page);
    await upload(page, 'left-pad-1.3.0.tgz');
    await expect(page.getByTestId('file-format')).toHaveText('npm package');
    await page.getByTestId('tab-components').click();
    await expect(page.getByTestId('component-row').filter({ hasText: 'left-pad' }).first()).toContainText('1.3.0');
    await page.getByTestId('tab-archive').click();
    await expect(page.getByTestId('archive-tree')).toContainText('package.json');
    expect(errors).toEqual([]);
  });

  test('jquery bundle and its source map', async ({ page }) => {
    const errors = watch(page);
    await upload(page, 'jquery.min.js');
    await page.getByTestId('tab-components').click();
    await expect(page.getByTestId('component-row').filter({ hasText: 'jquery' }).first()).toContainText('3.7.1');
    await page.getByRole('button', { name: 'Open another file' }).click();
    await page.getByTestId('file-input').setInputFiles(join(samples, 'jquery.min.map'));
    await expect(page.getByTestId('file-format')).toHaveText('Source map', { timeout: 30_000 });
    await expect(page.getByRole('tab', { name: /jquery\.min\.js/ })).toBeVisible();
    expect(errors).toEqual([]);
  });

  test('suspicious demo lights up secrets and rules', async ({ page }) => {
    const errors = watch(page);
    await page.goto('analyze');
    await page.getByTestId('sample-suspicious').click();
    await expect(page.getByTestId('tab-findings')).toBeVisible({ timeout: 30_000 });
    const score = Number(await page.getByTestId('risk-gauge').getAttribute('data-score'));
    expect(score).toBeGreaterThan(70);
    await page.getByTestId('tab-findings').click();
    const secret = page.getByTestId('finding').filter({ hasText: /AWS (secret access key|access key id) found/ });
    await expect(secret.first()).toBeVisible();
    expect(await page.locator('[data-testid="finding"][data-severity="critical"], [data-testid="finding"][data-severity="high"]').filter({ hasText: 'AWS' }).count()).toBeGreaterThan(0);
    await expect(page.getByTestId('findings-list')).toContainText('ATT&CK T1552.001');
    await page.screenshot({ path: join(shots, 'analyze-findings.png'), fullPage: false });
    await page.getByTestId('tab-rules').click();
    await expect(page.getByTestId('rule-match').filter({ hasText: 'Reverse_Shell_Strings' })).toBeVisible();
    expect(Number(await page.getByTestId('rules-match-count').textContent())).toBeGreaterThan(0);
    // A broken rule shows a readable error, then fixing it brings matches back.
    const editor = page.getByTestId('rules-editor');
    await editor.fill('rule Broken { strings: $a = "eval" condition: $a and nonsense }');
    await expect(page.getByTestId('rules-error')).toBeVisible();
    await editor.fill('rule Finds_Eval { strings: $a = "eval(atob" condition: $a }');
    await expect(page.getByTestId('rule-match').filter({ hasText: 'Finds_Eval' })).toBeVisible();
    await page.evaluate(() => localStorage.removeItem('revlens.rules'));
    expect(errors).toEqual([]);
  });

  test('export SARIF downloads valid SARIF 2.1.0', async ({ page }) => {
    await page.goto('analyze');
    await page.getByTestId('sample-suspicious').click();
    await expect(page.getByTestId('tab-export')).toBeVisible({ timeout: 30_000 });
    await page.getByTestId('tab-export').click();
    const [dl] = await Promise.all([page.waitForEvent('download'), page.getByTestId('export-sarif').click()]);
    expect(dl.suggestedFilename()).toMatch(/\.sarif$/);
    const path = await dl.path();
    const sarif = JSON.parse(readFileSync(path!, 'utf8')) as { version: string; runs: { results: unknown[] }[] };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]!.results.length).toBeGreaterThan(0);
  });

  test('entropy screenshot', async ({ page }) => {
    await upload(page, 'ls-linux.elf');
    await page.getByTestId('tab-entropy').click();
    await expect(page.getByTestId('entropy-chart')).toBeVisible();
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.getByTestId('entropy-bar').nth(20).hover();
    await page.waitForTimeout(300);
    await page.getByTestId('entropy-chart').screenshot({ path: join(shots, 'analyze-entropy.png') });
  });
});

test('diff two samples', async ({ page }) => {
  const errors = watch(page);
  await page.goto('diff');
  await page.getByTestId('diff-a-sample-jquery').click();
  await page.getByTestId('diff-b-sample-react-dom').click();
  await expect(page.getByTestId('diff-summary')).toContainText('Between jquery.min.js and react-dom.production.min.js', { timeout: 30_000 });
  await expect(page.getByTestId('diff-components')).toContainText('react-dom@18.3.1');
  await expect(page.getByTestId('diff-components')).toContainText('jquery@3.7.1');
  await page.screenshot({ path: join(shots, 'diff.png'), fullPage: true });
  expect(errors).toEqual([]);
});

test('verify claims against the ELF sample', async ({ page }) => {
  const errors = watch(page);
  await page.goto('verify');
  await page.getByTestId('verify-sample-elf').click();
  await expect(page.getByTestId('verify-run')).toBeEnabled({ timeout: 30_000 });
  await page.getByTestId('claim-kind').selectOption('format-is');
  await page.getByTestId('claim-format').selectOption('elf');
  await page.getByTestId('verify-run').click();
  await expect(page.getByTestId('verify-result')).toHaveAttribute('data-verdict', 'VERIFIED');
  await page.getByTestId('claim-kind').selectOption('bytes-at');
  await page.getByTestId('claim-offset').fill('0');
  await page.getByTestId('claim-hex').fill('7F454C46');
  await page.getByTestId('verify-run').click();
  await expect(page.getByTestId('verify-result')).toHaveAttribute('data-verdict', 'VERIFIED');
  await page.getByTestId('claim-kind').selectOption('has-section');
  await page.getByTestId('claim-name').fill('.definitely-not-here');
  await page.getByTestId('verify-run').click();
  await expect(page.getByTestId('verify-result')).toHaveAttribute('data-verdict', 'REFUTED');
  await page.getByTestId('claim-kind').selectOption('uses-component');
  await page.getByTestId('claim-name').fill('react-dom');
  await page.getByTestId('verify-run').click();
  await expect(page.getByTestId('verify-result')).toHaveAttribute('data-verdict', 'REFUTED');
  expect(errors).toEqual([]);
});

test('all four themes apply and persist', async ({ page }) => {
  await page.emulateMedia({ colorScheme: 'dark' });
  await page.goto('settings');
  for (const [id, expected] of [['black', 'black'], ['dark', 'dark'], ['sun', 'sun'], ['system', 'black']] as const) {
    await page.getByTestId(`theme-${id}`).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme', expected);
  }
  await page.getByTestId('theme-sun').click();
  await page.getByTestId('accent-teal').click();
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'sun');
  await expect(page.locator('html')).toHaveAttribute('data-accent', 'teal');
  await page.emulateMedia({ colorScheme: 'light' });
  await page.getByTestId('theme-system').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'sun');
});

test('command palette opens with Ctrl+K and jumps to a page', async ({ page }) => {
  await page.goto('');
  await expect(page.locator('h1').first()).toBeVisible();
  await page.locator('body').click({ position: { x: 5, y: 300 } });
  await page.keyboard.press('Control+k');
  const dialog = page.getByRole('dialog', { name: 'Command palette' });
  await expect(dialog).toBeVisible();
  const box = dialog.getByRole('textbox');
  await expect(box).toBeFocused();
  await box.fill('Verify');
  await expect(box).toHaveValue('Verify');
  await expect(page.getByRole('dialog', { name: 'Command palette' }).getByText('Verify', { exact: true }).first()).toBeVisible();
  await page.keyboard.press('Enter');
  await expect(page).toHaveURL(/\/re\/verify$/);
  await expect(page.locator('h1')).toContainText('Check a claim');
});

test('no purple or pink in the built CSS', async () => {
  const dist = join(here, '..', 'dist', 'assets');
  const css = readdirSync(dist).filter((f) => f.endsWith('.css')).map((f) => readFileSync(join(dist, f), 'utf8')).join('\n');
  expect(css).not.toMatch(/\b(purple|violet|fuchsia|pink|indigo|rose)-\d{2,3}\b/);
});

test.describe('no horizontal overflow', () => {
  for (const theme of ['black', 'sun'] as const) {
    for (const width of [360, 768, 1280]) {
      test(`${theme} at ${width}px`, async ({ page }) => {
        await page.setViewportSize({ width, height: 900 });
        await page.goto('');
        await setTheme(page, theme);
        const pages = ['', 'analyze', 'diff', 'verify', 'docs', 'blog', 'about', 'changelog', 'settings', ...docSlugs.slice(0, 2).map((s) => `docs/${s}`), ...postSlugs.slice(0, 2).map((s) => `blog/${s}`)];
        for (const p of pages) {
          await page.goto(p);
          await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
          await expect(page.locator('h1').first()).toBeVisible();
          const o = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth }));
          expect(o.sw, `overflow on /${p} at ${width}px in ${theme}`).toBeLessThanOrEqual(o.cw + 1);
        }
        // A loaded report too, on the findings and entropy tabs.
        await page.goto('analyze');
        await page.getByTestId('sample-suspicious').click();
        await expect(page.getByTestId('tab-findings')).toBeVisible({ timeout: 30_000 });
        for (const t of ['overview', 'findings', 'strings', 'rules', 'hex', 'export']) {
          await page.getByTestId(`tab-${t}`).click();
          await page.waitForTimeout(250);
          const o = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth }));
          expect(o.sw, `overflow on analyze tab ${t} at ${width}px in ${theme}`).toBeLessThanOrEqual(o.cw + 1);
        }
      });
    }
  }
});

test('home screenshots, desktop and mobile', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('');
  await expect(page.getByTestId('lens-hero')).toBeVisible();
  await page.waitForTimeout(1800);
  await page.screenshot({ path: join(shots, 'home-desktop.png') });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  await page.waitForTimeout(1800);
  await page.screenshot({ path: join(shots, 'home-mobile.png') });
});
