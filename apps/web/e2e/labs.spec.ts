// Tool pages: every route renders, every "try a sample" button produces the expected output from the
// real fixture, and nothing overflows sideways on phones, tablets or desktops.
import { test, expect, type Page } from '@playwright/test';

const LAB_ROUTES = ['labs', 'labs/disassembler', 'labs/mobile', 'labs/managed', 'labs/javascript', 'labs/electron', 'labs/network', 'labs/sqlite'];

function watch(page: Page): string[] {
  const errors: string[] = [];
  page.on('console', (m) => { if (m.type() === 'error') errors.push(`console: ${m.text()}`); });
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  return errors;
}

test.describe('tool routes', () => {
  for (const r of LAB_ROUTES) {
    test(`/${r} renders a heading without console errors`, async ({ page }) => {
      const errors = watch(page);
      const res = await page.goto(r);
      expect(res?.status()).toBeLessThan(400);
      await expect(page.locator('h1').first()).toBeVisible();
      await expect(page.locator('h1').first()).not.toBeEmpty();
      await page.waitForTimeout(300);
      expect(errors).toEqual([]);
    });
  }

  test('the tools index links to every tool page', async ({ page }) => {
    await page.goto('labs');
    for (const r of LAB_ROUTES.slice(1)) await expect(page.getByTestId(`lab-card-${r.split('/')[1]}`)).toBeVisible();
  });
});

test.describe('new docs pages', () => {
  for (const slug of ['disassembler', 'mobile', 'managed-runtimes', 'javascript-and-electron', 'network-and-data', 'extras', 'bridges', 'mcp-tools', 'agent-skills-and-plugins', 'comparison', 'stripped-elf-password-check', 'android-apk-review']) {
    test(`/docs/${slug} renders`, async ({ page }) => {
      const errors = watch(page);
      await page.goto(`docs/${slug}`);
      await expect(page.locator('h1').first()).toBeVisible();
      await expect(page.locator('h1').first()).not.toHaveText(/not found/i);
      expect(errors).toEqual([]);
    });
  }
});

// [route, sample button id, text the result must show]
const SAMPLES: [string, string, string][] = [
  ['labs/mobile', 'apk', 'classes.dex'],
  ['labs/mobile', 'dex', 'totalClasses'],
  ['labs/mobile', 'class', 'com.revlens.demo.Hello'],
  ['labs/mobile', 'ipa', 'org.wikimedia.wikipedia'],
  ['labs/managed', 'dotnet', '.NETCoreApp,Version=v8.0'],
  ['labs/managed', 'pyc', 'RESUME'],
  ['labs/managed', 'lua', 'VARARGPREP'],
  ['labs/managed', 'beam', 'elixir_sup'],
  ['labs/managed', 'evm', 'decimals()'],
  ['labs/javascript', 'obfuscated', 'telemetry.revlens-fixture.example'],
  ['labs/javascript', 'bundle', 'webpack5'],
  ['labs/javascript', 'map', 'webpack:///./api.js'],
  ['labs/electron', 'asar', 'nodeIntegration'],
  ['labs/network', 'dns', '209.87.249.18'],
  ['labs/network', 'tls', '74.125.239.152'],
  ['labs/network', 'har', 'Playwright 1.23.0-next'],
  ['labs/sqlite', 'db', 'CREATE TABLE users'],
];

test.describe('try a sample', () => {
  for (const [route, id, want] of SAMPLES) {
    test(`${route} sample ${id} shows ${want}`, async ({ page }) => {
      const errors = watch(page);
      await page.goto(route);
      await page.getByTestId(`sample-${id}`).click();
      await expect(page.getByTestId('tool-result')).toContainText(want, { timeout: 45_000 });
      expect(errors).toEqual([]);
    });
  }

  test('APK report leads with the manifest summary', async ({ page }) => {
    await page.goto('labs/mobile');
    await page.getByTestId('sample-apk').click();
    const summary = page.getByTestId('tool-summary');
    await expect(summary).toContainText('com.angrydoughnuts.android.alarmclock', { timeout: 45_000 });
    await expect(summary).toContainText('Target SDK');
    await expect(summary).toContainText('Permissions');
  });

  test('SQLite query runs a SELECT', async ({ page }) => {
    await page.goto('labs/sqlite');
    await page.getByTestId('sample-db').click();
    await expect(page.getByTestId('tool-result')).toBeVisible({ timeout: 30_000 });
    await page.getByTestId('tool-web_sqlite_query').click();
    await page.getByTestId('run-tool').click();
    await expect(page.getByTestId('tool-result')).toContainText('rowCount', { timeout: 30_000 });
  });

  test('disassembler: x86-64 ELF shows main with pseudo code, graph and listing', async ({ page }) => {
    const errors = watch(page);
    await page.goto('labs/disassembler');
    await page.getByTestId('sample-hello-x64-elf').click();
    await expect(page.getByTestId('function-name')).toHaveText('main', { timeout: 60_000 });
    await expect(page.getByTestId('pseudocode')).toContainText('hello from revlens');
    expect(await page.getByTestId('function-row').count()).toBeGreaterThan(5);
    await page.getByTestId('view-graph').click();
    await expect(page.getByTestId('cfg-block').first()).toBeVisible();
    await page.getByTestId('view-listing').click();
    await expect(page.getByTestId('listing')).toContainText('push');
    expect(errors).toEqual([]);
  });

  test('disassembler: AArch64 ELF decodes with Capstone', async ({ page }) => {
    await page.goto('labs/disassembler');
    await page.getByTestId('sample-hello-arm64-elf').click();
    await expect(page.getByTestId('function-name')).toHaveText('main', { timeout: 60_000 });
    await expect(page.getByTestId('disasm-info')).toContainText('arm64');
  });

  test('disassembler: PE executable lists functions', async ({ page }) => {
    await page.goto('labs/disassembler');
    await page.getByTestId('sample-hello-x64-exe').click();
    await expect(page.getByTestId('function-view')).toBeVisible({ timeout: 60_000 });
    expect(await page.getByTestId('function-row').count()).toBeGreaterThan(0);
  });

  test('analyze shows the combined report for a package format', async ({ page }) => {
    await page.goto('analyze');
    await page.getByTestId('file-input').setInputFiles({ name: 'dns_udp.pcap', mimeType: 'application/octet-stream', buffer: await (await page.request.get('samples/webrt/dns_udp.pcap')).body() });
    await expect(page.getByTestId('file-format')).toHaveText('Packet capture', { timeout: 30_000 });
  });
});

test.describe('no horizontal overflow on tool pages', () => {
  for (const theme of ['black', 'sun'] as const) for (const width of [360, 768, 1280]) {
    test(`tool pages at ${width}px in the ${theme} theme`, async ({ page }) => {
      await page.setViewportSize({ width, height: 900 });
      await page.goto('labs');
      await page.evaluate((t) => localStorage.setItem('revlens.settings', JSON.stringify({ theme: t, accent: 'gold', motion: 'reduced' })), theme);
      for (const r of LAB_ROUTES) {
        await page.goto(r);
        await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
        await expect(page.locator('h1').first()).toBeVisible();
        if (r === 'labs/disassembler') {
          await page.getByTestId('sample-hello-x64-elf').click();
          await expect(page.getByTestId('function-name')).toBeVisible({ timeout: 60_000 });
        } else if (r !== 'labs') {
          await page.locator('[data-testid^="sample-"]').first().click();
          await expect(page.getByTestId('tool-result')).toBeVisible({ timeout: 45_000 });
        }
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
        expect(overflow, `${r} overflows by ${overflow}px at ${width}px`).toBeLessThanOrEqual(0);
      }
    });
  }
});
