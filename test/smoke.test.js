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

test('Rejet d un code OTP invalide', async () => {
  const identifier = '+242060000222';
  const reqOtp = await fetch(`${BASE_URL}/api/otp/request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier })
  });
  assert.equal(reqOtp.status, 200);

  const badVerify = await fetch(`${BASE_URL}/api/otp/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier, code: '000000' })
  });
  assert.equal(badVerify.status, 400);
});

test('Rejet d un jeton malforme ou falsifie', async () => {
  const verifyBad = await fetch(`${BASE_URL}/api/token/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: 'cc1.invalid.signature' })
  });
  assert.ok(verifyBad.status >= 400 && verifyBad.status < 500);
});

test('Verification des scopes sur un jeton cc1.', async () => {
  const issueRes = await fetch(`${BASE_URL}/api/token/issue`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject: '+242060000333', scope: 'identity:verify' })
  });
  assert.equal(issueRes.status, 200);
  const issued = await issueRes.json();

  const forbiddenRes = await fetch(`${BASE_URL}/api/token/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: issued.token, requiredScope: 'profile:write' })
  });
  assert.equal(forbiddenRes.status, 403);

  const allowedRes = await fetch(`${BASE_URL}/api/token/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: issued.token, requiredScope: 'identity:verify' })
  });
  assert.equal(allowedRes.status, 200);
});

test('Revocation d un jeton cc1. et rejet apres revocation', async () => {
  const issueRes = await fetch(`${BASE_URL}/api/token/issue`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject: '+242060000444', scope: 'identity:verify' })
  });
  assert.equal(issueRes.status, 200);
  const issued = await issueRes.json();

  const revokeRes = await fetch(`${BASE_URL}/api/token/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: issued.token, reason: 'test_revocation' })
  });
  assert.equal(revokeRes.status, 200);
  const revoked = await revokeRes.json();
  assert.equal(revoked.revoked, true);

  const verifyAfterRevoke = await fetch(`${BASE_URL}/api/token/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: issued.token })
  });
  assert.equal(verifyAfterRevoke.status, 401);
});

test('Limitation de debit OTP par identifiant (429)', async () => {
  const identifier = '+242060000555';
  let got429 = false;

  for (let i = 0; i < 8; i += 1) {
    const res = await fetch(`${BASE_URL}/api/otp/request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier })
    });
    if (res.status === 429) {
      got429 = true;
      break;
    }
  }

  assert.equal(got429, true);
});
