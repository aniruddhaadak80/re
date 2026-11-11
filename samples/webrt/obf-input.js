// Known input for the javascript-obfuscator fixture. Tests assert these strings come back.
function buildRequest(user, token) {
  const endpoint = 'https://telemetry.revlens-fixture.example/collect';
  const headers = { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' };
  const payload = { id: user.id, name: user.name, plan: 'enterprise' };
  let attempts = 0;
  attempts += 1;
  const body = JSON.stringify(payload);
  console.log('sending payload', attempts);
  return fetch(endpoint, { method: 'POST', headers, body });
}

function checkLicense(key) {
  const secret = 'RL-LICENSE-SALT-2026';
  const valid = key.startsWith('RL-') && key.length === 20;
  if (!valid) {
    console.warn('invalid license key');
    return false;
  }
  return secret.length > 0;
}

buildRequest({ id: 7, name: 'ada' }, 'tok_live_123');
checkLicense('RL-ABCDEFGHIJKLMNOPQ');
