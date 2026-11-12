// EnvApp client. Named functions so runtime tracing can pick them by name.
const API = '/api';

function computeTotal(list, taxRate = 0) {
  let sum = 0;
  for (const it of list) sum += it.price;
  return Math.round(sum * (1 + taxRate));
}

function renderItems(list) {
  const ul = document.getElementById('list');
  ul.textContent = '';
  for (const it of list) {
    const li = document.createElement('li');
    li.className = 'item';
    li.dataset.id = String(it.id);
    li.textContent = `${it.id}: ${it.name}`;
    li.addEventListener('click', () => showItem(it.id));
    ul.appendChild(li);
  }
  document.getElementById('total').textContent = String(computeTotal(list));
}

async function loadItems() {
  const res = await fetch(`${API}/items`);
  const data = await res.json();
  renderItems(data.items);
  return data.total;
}

async function showItem(id) {
  const res = await fetch(`${API}/items/${id}`);
  const it = await res.json();
  document.getElementById('detail').textContent = `${it.name} costs ${it.price}`;
}

async function addItem(name) {
  const res = await fetch('/api/items', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name }) });
  await res.json();
  return loadItems();
}

function loadSession() {
  const xhr = new XMLHttpRequest();
  xhr.open('GET', '/api/session');
  xhr.onload = () => { document.getElementById('user').textContent = JSON.parse(xhr.responseText).user; };
  xhr.send();
}

async function search(q) {
  const res = await fetch(`/api/search?q=${encodeURIComponent(q)}&page=1`);
  const data = await res.json();
  document.getElementById('hits').textContent = data.hits.join(',');
}

// never called: a hidden admin endpoint and a telemetry host that only static analysis can see
async function exportAll() {
  await fetch('/api/admin/export', { method: 'POST' });
  navigator.sendBeacon('https://telemetry.envapp.example/collect', 'x');
}

// built at run time from parts, so static analysis cannot see the path
function dynamicPath(n) {
  return ['', 'api', 'dyn', 'part-' + n].join('/');
}

async function loadDynamic() {
  const res = await fetch(dynamicPath(7));
  document.getElementById('dyn').textContent = (await res.json()).echo;
}

document.getElementById('add').addEventListener('click', () => addItem(document.getElementById('name').value));
document.getElementById('search').addEventListener('click', () => search(document.getElementById('q').value));
setTimeout(() => { fetch(`${API}/ping`); }, 50);
loadSession();
loadItems().then(() => loadDynamic());
window.__envapp = { exportAll };
