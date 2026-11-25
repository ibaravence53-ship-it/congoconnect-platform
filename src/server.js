const http = require('http');
const fs = require('fs');
const path = require('path');
const config = require('./config/env');
const { requestOtp, verifyOtp } = require('./services/otpService');
const { lookupIdentity } = require('./services/identityProviderSim');
const { listProviders } = require('./services/serviceProviderRegistry');
const { recordAudit, listAuditLogs, buildAuditSummary } = require('./services/auditLogService');
const { issueToken, verifyToken, revokeToken , isTokenRevokedAsync: _pkiIsRevokedAsync, isTokenRevoked: _pkiIsRevoked} = require('./services/pkiService');
const { checkRateLimitAsync } = require('./services/rateLimiter');
const { createServiceRequest, updateRequestStatus } = require('./services/requestService');


async function isTokenRevokedAsync(jti) {
  if (!jti) return false;
  if (typeof _pkiIsRevokedAsync === 'function') return Boolean(await _pkiIsRevokedAsync(jti));
  if (typeof _pkiIsRevoked === 'function') return Boolean(await _pkiIsRevoked(jti));
  return false;
}

const port = config.port;
const hideOtp = config.hideOtpInResponse;
const indexHtmlPath = path.join(__dirname, '..', 'public', 'index.html');

const otpRateBuckets = new Map();
const OTP_WINDOW_MS = 60 * 1000;
const OTP_MAX_REQUESTS = 10;

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim()) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function allowOtpRequest(ip) {
  const now = Date.now();
  const entry = otpRateBuckets.get(ip);
  if (!entry || now - entry.windowStart >= OTP_WINDOW_MS) {
    otpRateBuckets.set(ip, { windowStart: now, count: 1 });
    return { allowed: true, retryAfterSec: 0 };
  }
  if (entry.count >= OTP_MAX_REQUESTS) {
    const retryAfterSec = Math.ceil((OTP_WINDOW_MS - (now - entry.windowStart)) / 1000);
    return { allowed: false, retryAfterSec };
  }
  entry.count += 1;
  return { allowed: true, retryAfterSec: 0 };
}

function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  setSecurityHeaders(res);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extraHeaders
  });
  res.end(JSON.stringify(payload));
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk.toString('utf8');
      if (raw.length > 1024 * 64) {
        reject(new Error('Corps de requete trop volumineux'));
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!raw.trim()) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (err) {
        reject(new Error('JSON invalide'));
      }
    });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost:' + port);

  if (req.method === 'GET' && url.pathname === '/app') {
    fs.readFile(indexHtmlPath, 'utf8', (err, html) => {
      if (err) {
        sendJson(res, 500, { status: 'error', message: 'Impossible de charger public/index.html' });
        return;
      }
      setSecurityHeaders(res);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/') {
    sendJson(res, 200, {
      status: 'ok',
      service: 'CongoConnect',
      storageMode: config.storageMode,
      routes: [
        'GET /',
        'GET /app',
        'GET /health',
        'POST /api/otp/request',
        'POST /api/otp/verify',
        'POST /api/identity/lookup',
        'GET /api/providers',
        'POST /api/token/issue',
        'POST /api/token/verify',
        'POST /api/token/revoke',
        'GET /api/audit'
      ]
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/health') {
    sendJson(res, 200, {
      status: 'ok',
      service: 'CongoConnect',
      storageMode: config.storageMode,
      adapters: {
        redis: {
          configured: Boolean(config.redisUrl),
          mode: config.storageMode.otp
        },
        postgres: {
          configured: Boolean(config.databaseUrl),
          mode: config.storageMode.audit
        }
      },
      uptimeSeconds: Math.floor(process.uptime()),
      timestamp: new Date().toISOString()
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/otp/request') {
    const ip = getClientIp(req);
    const rate = allowOtpRequest(ip);
    if (!rate.allowed) {
      recordAudit({
        event: 'OTP_REQUEST_RATE_LIMITED',
        identifier: '',
        outcome: 'denied',
        details: 'ip=' + ip + ', retry=' + rate.retryAfterSec + 's'
      });
      sendJson(
        res,
        429,
        {
          status: 'error',
          message: 'Trop de requetes OTP. Reessayez plus tard.',
          retryAfterSeconds: rate.retryAfterSec
        },
        { 'Retry-After': String(rate.retryAfterSec) }
      );
      return;
    }

    try {
      const body = await readJsonBody(req);
      const cleanId = typeof body.identifier === 'string' ? body.identifier.trim() : '';
      if (cleanId) {
        const idRate = await checkRateLimitAsync('otp-id:' + cleanId, 5, 60 * 1000);
        if (!idRate.allowed) {
          recordAudit({
            event: 'OTP_REQUEST_RATE_LIMITED',
            identifier: cleanId,
            outcome: 'denied',
            details: 'scope=identifier, retry=' + idRate.retryAfterSeconds + 's'
          });
          sendJson(
            res,
            429,
            {
              status: 'error',
              message: 'Trop de requetes OTP pour cet identifiant. Reessayez plus tard.',
              retryAfterSeconds: idRate.retryAfterSeconds
            },
            { 'Retry-After': String(idRate.retryAfterSeconds) }
          );
          return;
        }
      }

      const result = requestOtp(body.identifier);
      if (!result.ok) {
        recordAudit({
          event: 'OTP_REQUEST',
          identifier: body.identifier || '',
          outcome: 'error',
          details: result.error
        });
        sendJson(res, 400, { status: 'error', message: result.error });
        return;
      }
      recordAudit({
        event: 'OTP_REQUEST',
        identifier: result.identifier,
        outcome: 'success',
        details: 'ttl=' + result.expiresInSeconds + 's'
      });
      const payload = {
        status: 'ok',
        identifier: result.identifier,
        expiresInSeconds: result.expiresInSeconds,
        expiresAt: result.expiresAt
      };
      if (!hideOtp) {
        payload.otp = result.code;
      }
      sendJson(res, 200, payload);
    } catch (err) {
      sendJson(res, 400, { status: 'error', message: err.message });
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/otp/verify') {
    const ip = getClientIp(req);
    const rate = allowOtpRequest(ip);
    if (!rate.allowed) {
      recordAudit({
        event: 'OTP_VERIFY_RATE_LIMITED',
        identifier: '',
        outcome: 'denied',
        details: `ip=${ip}`
      });
      sendJson(
        res,
        429,
        {
          status: 'error',
          message: 'Trop de tentatives de verification OTP.',
          retryAfterSeconds: rate.retryAfterSec
        },
        { 'Retry-After': String(rate.retryAfterSec) }
      );
      return;
    }

    try {
      const body = await readJsonBody(req);
      const result = verifyOtp(body.identifier, body.code);
      if (!result.ok) {
        recordAudit({
          event: 'OTP_VERIFY',
          identifier: body.identifier || '',
          outcome: 'error',
          details: result.error
        });
        sendJson(res, 400, { status: 'error', message: result.error });
        return;
      }
      recordAudit({
        event: 'OTP_VERIFY',
        identifier: result.identifier,
        outcome: 'success',
        details: 'verified=true'
      });
      sendJson(res, 200, {
        status: 'ok',
        identifier: result.identifier,
        verified: result.verified
      });
    } catch (err) {
      sendJson(res, 400, { status: 'error', message: err.message });
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/identity/lookup') {
    try {
      const body = await readJsonBody(req);
      const result = lookupIdentity(body.identifier);
      if (!result.ok) {
        recordAudit({
          event: 'IDENTITY_LOOKUP',
          identifier: body.identifier || '',
          outcome: 'error',
          details: result.error
        });
        sendJson(res, 400, { status: 'error', message: result.error });
        return;
      }
      recordAudit({
        event: 'IDENTITY_LOOKUP',
        identifier: result.profile.identifier,
        outcome: 'success',
        details: `loa=${result.profile.verifiedLevel}`
      });
      sendJson(res, 200, {
        status: 'ok',
        profile: result.profile
      });
    } catch (err) {
      sendJson(res, 400, { status: 'error', message: err.message });
    }
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/providers') {
    const category = url.searchParams.get('category') || '';
    const items = listProviders(category);
    sendJson(res, 200, {
      status: 'ok',
      count: items.length,
      providers: items
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/token/issue') {
    try {
      const body = await readJsonBody(req);
      const result = issueToken({
        subject: body.subject || body.identifier,
        scope: body.scope,
        ttlSeconds: body.ttlSeconds
      });
      if (!result.ok) {
        recordAudit({
          event: 'TOKEN_ISSUE',
          identifier: body.subject || body.identifier || '',
          outcome: 'error',
          details: result.error
        });
        sendJson(res, 400, { status: 'error', message: result.error });
        return;
      }
      recordAudit({
        event: 'TOKEN_ISSUE',
        identifier: result.claims.sub,
        outcome: 'success',
        details: `jti=${result.claims.jti}, scope=${result.claims.scope}`
      });
      sendJson(res, 200, {
        status: 'ok',
        token: result.token,
        expiresInSeconds: result.expiresInSeconds,
        expiresAt: result.expiresAt,
        claims: result.claims
      });
    } catch (err) {
      sendJson(res, 400, { status: 'error', message: err.message });
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/token/verify') {
    try {
      const body = await readJsonBody(req);
      const requiredScope = body.requiredScope || body.scope || '';
      const result = verifyToken(body.token, { requiredScope });
      if (!result.ok) {
        recordAudit({
          event: 'TOKEN_VERIFY',
          identifier: result.claims && result.claims.sub ? result.claims.sub : '',
          outcome: 'error',
          details: requiredScope ? result.error + ' (requiredScope=' + requiredScope + ')' : result.error
        });
        sendJson(res, result.status || 400, { status: 'error', valid: false, message: result.error });
        return;
      }
      recordAudit({
        event: 'TOKEN_VERIFY',
        identifier: result.claims.sub,
        outcome: 'success',
        details: 'jti=' + result.claims.jti + ', scope=' + result.claims.scope
      });
      sendJson(res, 200, {
        status: 'ok',
        valid: true,
        claims: result.claims
      });
    } catch (err) {
      sendJson(res, 400, { status: 'error', message: err.message });
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/qr/verify') {
    const body = await readJsonBody(req);
    let rawToken = typeof body.token === 'string' ? body.token.trim() : '';
    let requiredScope = typeof body.requiredScope === 'string' ? body.requiredScope.trim() : '';

    if (!rawToken && typeof body.qrPayload === 'string') {
      const payloadStr = body.qrPayload.trim();
      if (payloadStr.startsWith('{')) {
        try {
          const parsed = JSON.parse(payloadStr);
          rawToken = typeof parsed.token === 'string' ? parsed.token.trim() : '';
          if (!requiredScope && typeof parsed.requiredScope === 'string') {
            requiredScope = parsed.requiredScope.trim();
          }
        } catch (_) {
          // Traite la charge utile brute comme un jeton si ce n'est pas un JSON valide
        }
      }
      if (!rawToken) {
        rawToken = payloadStr;
      }
    }

    const result = verifyToken(rawToken, { requiredScope: requiredScope || undefined });
    const revokedAsync = result.claims?.jti ? await isTokenRevokedAsync(result.claims.jti) : false;

    if (!result.ok || revokedAsync) {
      const statusCode = revokedAsync ? 401 : (result.status || 400);
      const errorMsg = revokedAsync ? 'Jeton revoque' : result.error;
      recordAudit({
        event: 'TOKEN_VERIFY',
        identifier: result.claims?.sub || 'unknown',
        outcome: 'error',
        details: 'qr_verify:' + errorMsg
      });
      return sendJson(res, statusCode, { ok: false, error: errorMsg, claims: result.claims || null });
    }

    recordAudit({
      event: 'TOKEN_VERIFY',
      identifier: result.claims?.sub || 'unknown',
      outcome: 'success',
      details: 'qr_verify:jti=' + result.claims.jti
    });
    return sendJson(res, 200, { ok: true, valid: true, claims: result.claims });
  }


  if (req.method === 'POST' && url.pathname === '/api/token/inspect') {
    try {
      const body = await readJsonBody(req);
      const token = typeof body.token === 'string' ? body.token.trim() : '';
      const writeAudit = body.audit !== false;

      if (!token) {
        sendJson(res, 400, { status: 'error', message: 'Jeton requis.' });
        return;
      }

      const verified = await verifyToken(token, { allowExpired: true, allowRevoked: true });
      const claims = verified && verified.claims ? verified.claims : null;
      const nowSec = Math.floor(Date.now() / 1000);
      const expired = claims && typeof claims.exp === 'number' ? claims.exp <= nowSec : false;
      const revoked = Boolean(verified && verified.revoked);
      const signatureValid = Boolean(verified && verified.valid !== false && claims);

      if (writeAudit) {
        recordAudit({
          event: 'TOKEN_INSPECT',
          identifier: claims && claims.sub ? claims.sub : '',
          outcome: signatureValid ? 'success' : 'denied',
          details: 'jti=' + (claims && claims.jti ? claims.jti : 'n/a') + ', revoked=' + revoked + ', expired=' + expired
        });
      }

      sendJson(res, 200, {
        status: 'ok',
        active: Boolean(signatureValid && !revoked && !expired),
        signatureValid,
        revoked,
        expired,
        claims: claims
          ? {
              sub: claims.sub || null,
              scope: claims.scope || null,
              jti: claims.jti || null,
              iat: claims.iat || null,
              exp: claims.exp || null
            }
          : null
      });
    } catch (err) {
      sendJson(res, 400, { status: 'error', message: err.message || 'Inspection impossible.' });
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/token/revoke') {
    try {
      const body = await readJsonBody(req);
      const result = await revokeToken(body.token, body.reason || 'manual_revocation');
      if (!result.ok) {
        recordAudit({
          event: 'TOKEN_REVOKE',
          identifier: result.claims && result.claims.sub ? result.claims.sub : '',
          outcome: 'error',
          details: result.error
        });
        sendJson(res, result.status || 400, { status: 'error', revoked: false, message: result.error });
        return;
      }
      recordAudit({
        event: 'TOKEN_REVOKE',
        identifier: result.claims.sub,
        outcome: 'success',
        details: 'jti=' + result.jti + ', reason=' + result.reason
      });
      sendJson(res, 200, {
        status: 'ok',
        revoked: true,
        jti: result.jti,
        expiresAt: result.expiresAt
      });
    } catch (err) {
      sendJson(res, 400, { status: 'error', message: err.message });
    }
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/requests') {
    const body = await readJsonBody(req);
    const created = createServiceRequest({
      identifier: body.identifier,
      providerId: body.providerId,
      amount: body.amount,
      purpose: body.purpose
    });

    if (!created.ok) {
      recordAudit('REQUEST_CREATE_REJECTED', body.identifier || 'unknown', 'error', created.error);
      return sendJson(res, 400, { status: 'error', message: created.error });
    }

    recordAudit('REQUEST_CREATED', created.request.identifier, 'ok', 'id=' + created.request.id + ',provider=' + created.request.providerId);
    return sendJson(res, 201, { status: 'ok', request: created.request });
  }

    const statusMatch = req.method === 'PATCH' ? url.pathname.match(/^\/api\/requests\/([^/]+)\/status$/) : null;
  if (statusMatch) {
    const reqId = decodeURIComponent(statusMatch[1]);
    const body = await readJsonBody(req);
    const nextStatus = body && body.status ? body.status : '';
    const updated = updateRequestStatus(reqId, nextStatus);

    if (!updated.ok) {
      const statusCode = updated.error && updated.error.startsWith('Demande introuvable') ? 404 : 400;
      recordAudit('REQUEST_STATUS_REJECTED', reqId, 'error', updated.error || 'statut invalide');
      return sendJson(res, statusCode, { status: 'error', message: updated.error });
    }

    recordAudit('REQUEST_STATUS_UPDATED', updated.request.identifier, 'ok', 'id=' + updated.request.id + ',status=' + updated.request.status);
    return sendJson(res, 200, { status: 'ok', request: updated.request });
  }


  if (req.method === 'GET' && url.pathname === '/api/requests/summary') {
    const reqSvc = require('./services/requestService');
    const items = typeof reqSvc.listServiceRequests === 'function' ? await reqSvc.listServiceRequests({}) : [];
    const byStatus = { created: 0, processing: 0, completed: 0, cancelled: 0 };
    const enriched = [];

    for (const r of (Array.isArray(items) ? items : [])) {
      const st = r && r.status ? r.status : 'created';
      byStatus[st] = (byStatus[st] || 0) + 1;
      let otpVerified = Boolean(r && r.otpVerified);
      if (!otpVerified && typeof reqSvc.isOtpVerified === 'function' && r && r.identifier) {
        otpVerified = Boolean(await reqSvc.isOtpVerified(r.identifier));
      }
      enriched.push({ ...r, otpVerified });
    }

    sendJson(res, 200, {
      status: 'ok',
      total: enriched.length,
      byStatus,
      requests: enriched
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/audit/export') {
    const format = (url.searchParams.get('format') || 'json').trim().toLowerCase();
    const limit = url.searchParams.get('limit') || '100';
    const event = url.searchParams.get('event') || '';
    const outcome = url.searchParams.get('outcome') || '';
    const logs = listAuditLogs({ limit, event, outcome });

    if (format === 'csv') {
      const escapeCsv = (val) => '"' + String(val ?? '').replace(/"/g, '""') + '"';
      const header = ['timestamp', 'event', 'outcome', 'identifierMasked', 'details'].join(',');
      const rows = logs.map((item) => [
        escapeCsv(item.timestamp),
        escapeCsv(item.event),
        escapeCsv(item.outcome),
        escapeCsv(item.identifierMasked),
        escapeCsv(item.details)
      ].join(','));
      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="congoconnect-audit.csv"'
      });
      return res.end([header, ...rows].join("\n"));
    }

    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': 'attachment; filename="congoconnect-audit.json"'
    });
    return res.end(JSON.stringify({ count: logs.length, logs }, null, 2));
  }

  if (req.method === 'GET' && url.pathname === '/api/audit') {
    const limit = url.searchParams.get('limit') || '30';
    const event = url.searchParams.get('event') || '';
    const outcome = url.searchParams.get('outcome') || '';
    const logs = listAuditLogs({ limit, event, outcome });
    sendJson(res, 200, {
      status: 'ok',
      count: logs.length,
      filters: {
        event: event || null,
        outcome: outcome || null,
        limit: Number(limit) || 30
      },
      logs
    });
    return;
  }

  sendJson(res, 404, {
    status: 'error',
    message: 'Route introuvable',
    path: url.pathname
  });
});

server.listen(port, () => {
  console.log('CongoConnect en ecoute sur http://localhost:' + port);
});





