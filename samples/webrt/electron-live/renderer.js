// Renderer code with named functions so tracing and coverage can name them. Written for RevLens (MIT).
const api = new URLSearchParams(location.search).get('api') || '';

async function doPing() {
  const who = document.getElementById('who').value;
  document.getElementById('out').textContent = await window.fixture.ping(who);
}

function renderItems(items) {
  const ul = document.getElementById('items');
  ul.textContent = '';
  for (const it of items) { const li = document.createElement('li'); li.className = 'item'; li.textContent = it.name; ul.appendChild(li); }
}

async function loadItems() {
  const res = await fetch(`${api}/api/items`);
  renderItems((await res.json()).items);
}

document.getElementById('ping').addEventListener('click', doPing);
document.getElementById('load').addEventListener('click', loadItems);
