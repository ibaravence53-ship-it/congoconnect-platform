const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { listProviders } = require('./serviceProviderRegistry');
const { isOtpVerified } = require('./otpService');

const dataDir = path.join(__dirname, '..', '..', 'data');
const dataFile = path.join(dataDir, 'requests.json');
const ALLOWED_STATUSES = ['created', 'processing', 'completed', 'cancelled'];
const OTP_REQUIRED_STATUSES = ['processing', 'completed'];

function loadRequests() {
  try {
    if (!fs.existsSync(dataFile)) return [];
    const raw = fs.readFileSync(dataFile, 'utf8').trim();
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function saveRequests(items) {
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(dataFile, JSON.stringify(items, null, 2), 'utf8');
}

const requestsStore = loadRequests();

function createServiceRequest({ identifier, providerId, amount, purpose }) {
  const cleanId = typeof identifier === 'string' ? identifier.trim() : '';
  const cleanProvider = typeof providerId === 'string' ? providerId.trim() : '';

  if (!cleanId || !cleanProvider) {
    return { ok: false, error: 'identifier et providerId sont requis' };
  }

  const providerExists = listProviders().some((p) => p.id === cleanProvider);
  if (!providerExists) {
    return { ok: false, error: 'Fournisseur inconnu : ' + cleanProvider };
  }

  const numericAmount = amount === undefined || amount === null || amount === '' ? 0 : Number(amount);
  if (!Number.isFinite(numericAmount) || numericAmount < 0) {
    return { ok: false, error: 'Montant invalide' };
  }

  const record = {
    id: 'REQ-' + crypto.randomBytes(3).toString('hex').toUpperCase(),
    identifier: cleanId,
    providerId: cleanProvider,
    amount: numericAmount,
    purpose: typeof purpose === 'string' && purpose.trim() ? purpose.trim() : 'Demande service CongoConnect',
    status: 'created',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  requestsStore.unshift(record);
  saveRequests(requestsStore);
  return { ok: true, request: record };
}

function updateRequestStatus(id, nextStatus) {
  const cleanId = typeof id === 'string' ? id.trim() : '';
  const cleanStatus = typeof nextStatus === 'string' ? nextStatus.trim() : '';

  if (!ALLOWED_STATUSES.includes(cleanStatus)) {
    return { ok: false, error: 'Statut invalide. Valeurs autorisees : ' + ALLOWED_STATUSES.join(', ') };
  }

  const item = requestsStore.find((r) => r.id === cleanId);
  if (!item) {
    return { ok: false, error: 'Demande introuvable : ' + cleanId };
  }

  if (OTP_REQUIRED_STATUSES.includes(cleanStatus) && !isOtpVerified(item.identifier)) {
    return {
      ok: false,
      error: 'OTP non verifie pour ' + item.identifier + ' (requis pour passer en ' + cleanStatus + ')'
    };
  }

  item.status = cleanStatus;
  item.updatedAt = new Date().toISOString();
  saveRequests(requestsStore);
  return { ok: true, request: item };
}

function deleteServiceRequest(id) {
  const cleanId = typeof id === 'string' ? id.trim() : '';
  const idx = requestsStore.findIndex((r) => r.id === cleanId);
  if (idx === -1) {
    return { ok: false, error: 'Demande introuvable : ' + cleanId };
  }
  const [removed] = requestsStore.splice(idx, 1);
  saveRequests(requestsStore);
  return { ok: true, deleted: removed };
}

function listServiceRequests({ q, status } = {}) {
  const cleanQ = typeof q === 'string' ? q.trim().toLowerCase() : '';
  const cleanStatus = typeof status === 'string' ? status.trim() : '';

  return requestsStore.filter((item) => {
    const matchStatus = !cleanStatus || cleanStatus === 'all' || item.status === cleanStatus;
    const matchQ =
      !cleanQ ||
      String(item.id || '').toLowerCase().includes(cleanQ) ||
      String(item.identifier || '').toLowerCase().includes(cleanQ) ||
      String(item.providerId || '').toLowerCase().includes(cleanQ) ||
      String(item.purpose || '').toLowerCase().includes(cleanQ);
    return matchStatus && matchQ;
  });
}

module.exports = {
  createServiceRequest,
  updateRequestStatus,
  deleteServiceRequest,
  listServiceRequests
};
