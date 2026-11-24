const { test } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');

const port = Number(process.env.PORT || 3000);
const host = 'localhost';

function reqJson(method, reqPath, body) {
  return new Promise((resolve, reject) => {
    const payload = body !== undefined ? JSON.stringify(body) : null;
    const req = http.request(
      {
        hostname: host,
        port,
        path: reqPath,
        method,
        headers: payload
          ? {
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(payload)
            }
          : {}
      },
      (res) => {
        let raw = '';
        res.on('data', (c) => {
          raw += c.toString('utf8');
        });
        res.on('end', () => {
          let data = null;
          try {
            data = raw ? JSON.parse(raw) : null;
          } catch {
            data = raw;
          }
          resolve({ status: res.statusCode, data });
        });
      }
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

test('Parcours complet CongoConnect sur localhost:3000', async () => {
  const uniqueIdentifier = '+24206' + String(Date.now()).slice(-6);

  const health = await reqJson('GET', '/health');
  assert.strictEqual(health.status, 200, 'GET /health doit retourner 200');

  const badProv = await reqJson('POST', '/api/requests', {
    identifier: uniqueIdentifier,
    providerId: 'fournisseur-inexistant',
    amount: 1000
  });
  assert.strictEqual(badProv.status, 400, 'Fournisseur inconnu doit retourner 400');

  const createdRes = await reqJson('POST', '/api/requests', {
    identifier: uniqueIdentifier,
    providerId: 'momo-cg',
    amount: 2500,
    purpose: 'Smoke test'
  });
  assert.strictEqual(createdRes.status, 201, 'Creation demande doit retourner 201');
  const reqId = createdRes.data.request.id;
  assert.ok(reqId, 'ID de demande attendu');

  const beforeOtpPatch = await reqJson('PATCH', '/api/requests/' + encodeURIComponent(reqId) + '/status', {
    status: 'completed'
  });
  assert.strictEqual(beforeOtpPatch.status, 400, 'Sans OTP verifie, passage en completed doit retourner 400');

  const otpReq = await reqJson('POST', '/api/otp/request', { identifier: uniqueIdentifier });
  const otpBody = otpReq.data || {};
  const otpCode = otpBody.otp || otpBody.code || otpBody.otpCode;
  assert.ok(otpCode, 'Code OTP attendu');

  const otpVer = await reqJson('POST', '/api/otp/verify', {
    identifier: uniqueIdentifier,
    code: otpCode
  });
  assert.strictEqual(otpVer.status, 200, 'Verification OTP doit retourner 200');

  const patchRes = await reqJson('PATCH', '/api/requests/' + encodeURIComponent(reqId) + '/status', {
    status: 'completed'
  });
  assert.strictEqual(patchRes.status, 200, 'Avec OTP verifie, mise a jour statut doit retourner 200');
  assert.strictEqual(patchRes.data.request.status, 'completed');

  const listRes = await reqJson('GET', '/api/requests?status=completed');
  assert.strictEqual(listRes.status, 200, 'GET /api/requests filtre doit retourner 200');
  assert.ok(
    listRes.data.requests.some((r) => r.id === reqId),
    'La demande completee doit apparaitre dans le filtre'
  );

  const delRes = await reqJson('DELETE', '/api/requests/' + encodeURIComponent(reqId));
  assert.strictEqual(delRes.status, 200, 'Suppression demande doit retourner 200');
});
