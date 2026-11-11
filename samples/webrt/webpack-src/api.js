export const API_BASE = 'https://api.revlens-fixture.example/v2';

export async function getUser(id) {
  const res = await fetch(`${API_BASE}/users/${id}`, { method: 'GET', headers: { 'X-Client': 'fixture' } });
  return res.json();
}

export function saveSettings(settings) {
  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/settings');
  xhr.send(JSON.stringify(settings));
}

export function openLive() {
  return new WebSocket('wss://live.revlens-fixture.example/socket');
}
