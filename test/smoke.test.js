const test = require('node:test');
const assert = require('node:assert/strict');

const BASE_URL = process.env.CONGOCONNECT_URL || 'http://localhost:3000';

test('GET /health retourne ok', async () => {
  const res = await fetch(`${BASE_URL}/health`);
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.status, 'ok');
});

test('GET /app retourne la page HTML', async () => {
  const res = await fetch(`${BASE_URL}/app`);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.ok(html.includes('CongoConnect'));
});

test('Flux OTP complet : demande, validation puis rejet en relecture', async () => {
  const identifier = '+242060000111';

  const reqOtp = await fetch(`${BASE_URL}/api/otp/request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier })
  });
  assert.equal(reqOtp.status, 200);
  const otpData = await reqOtp.json();
  assert.match(otpData.otp, /^\d{6}$/);

  const verifyOk = await fetch(`${BASE_URL}/api/otp/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier, code: otpData.otp })
  });
  assert.equal(verifyOk.status, 200);
  const verifiedData = await verifyOk.json();
  assert.equal(verifiedData.verified, true);

  const replay = await fetch(`${BASE_URL}/api/otp/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier, code: otpData.otp })
  });
  assert.equal(replay.status, 400);
});

test('Emission et verification de jeton PKI simule + journal audit', async () => {
  const issueRes = await fetch(`${BASE_URL}/api/token/issue`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject: '+242060000000', scope: 'identity:verify' })
  });
  assert.equal(issueRes.status, 200);
  const issued = await issueRes.json();
  assert.ok(issued.token.startsWith('cc1.'));

  const verifyRes = await fetch(`${BASE_URL}/api/token/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: issued.token })
  });
  assert.equal(verifyRes.status, 200);
  const verified = await verifyRes.json();
  assert.equal(verified.valid, true);

  const auditRes = await fetch(`${BASE_URL}/api/audit?limit=5`);
  assert.equal(auditRes.status, 200);
  const auditData = await auditRes.json();
  assert.ok(Array.isArray(auditData.logs));
});
