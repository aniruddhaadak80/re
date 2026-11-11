export function renderDashboard(user) {
  const el = document.createElement('div');
  el.textContent = 'Dashboard for ' + user.id;
  navigator.sendBeacon('/telemetry/dashboard-open', JSON.stringify({ id: user.id }));
  document.body.appendChild(el);
}
