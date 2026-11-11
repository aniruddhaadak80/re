import { getUser, API_BASE } from './api.js';
import { formatName } from './util/format.js';

const DEBUG = process.env.DEBUG_MODE;

async function main() {
  const user = await getUser(42);
  console.log(formatName(user), API_BASE, DEBUG);
  if (window.featureFlags && window.featureFlags.isEnabled('new-dashboard')) {
    const { renderDashboard } = await import('./dashboard.js');
    renderDashboard(user);
  }
}

main();
