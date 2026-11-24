const http = require('http');
const fs = require('fs');
const path = require('path');
const config = require('./config/env');
const { requestOtp, verifyOtp } = require('./services/otpService');
const { lookupIdentity } = require('./services/identityProviderSim');
const { listProviders } = require('./services/serviceProviderRegistry');
const { recordAudit, listAuditLogs } = require('./services/auditLogService');
const { issueToken, verifyToken } = require('./services/pkiService');
const { createServiceRequest, updateRequestStatus } = require('./services/requestService');

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
        details: `ip=${ip}, retry=${rate.retryAfterSec}s`
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
        details: `ttl=${result.expiresInSeconds}s`
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
      const result = verifyToken(body.token);
      if (!result.ok) {
        recordAudit({
          event: 'TOKEN_VERIFY',
          identifier: result.claims && result.claims.sub ? result.claims.sub : '',
          outcome: 'error',
          details: result.error
        });
        sendJson(res, 400, { status: 'error', valid: false, message: result.error });
        return;
      }
      recordAudit({
        event: 'TOKEN_VERIFY',
        identifier: result.claims.sub,
        outcome: 'success',
        details: `jti=${result.claims.jti}`
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

  if (req.method === 'GET' && url.pathname === '/api/audit') {
    const limit = url.searchParams.get('limit') || '30';
    const logs = listAuditLogs(limit);
    sendJson(res, 200, {
      status: 'ok',
      count: logs.length,
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


