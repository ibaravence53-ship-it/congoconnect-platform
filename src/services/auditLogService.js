const {
  appendAuditEntry,
  persistAuditEntryToPg,
  readAuditEntries
} = require('../storage/auditStore');

function maskIdentifier(value) {
  if (typeof value !== 'string' || !value.trim()) return 'unknown';
  const clean = value.trim();
  if (clean.length <= 4) return '***';
  return `${clean.slice(0, 3)}***${clean.slice(-3)}`;
}

function recordAudit({ event, identifier = '', outcome = 'success', details = '' }) {
  const entry = {
    timestamp: new Date().toISOString(),
    event,
    identifierMasked: maskIdentifier(identifier),
    outcome,
    details
  };

  appendAuditEntry(entry);
  void persistAuditEntryToPg({
    eventTime: entry.timestamp,
    eventType: entry.event,
    identifierMasked: entry.identifierMasked,
    outcome: entry.outcome,
    details: entry.details
  }).catch(() => {});

  return entry;
}

function listAuditLogs(options = 30) {
  const opts = typeof options === 'object' && options !== null
    ? options
    : { limit: options };

  const numericLimit = Number(opts.limit);
  const safeLimit = Number.isFinite(numericLimit) && numericLimit > 0
    ? Math.min(200, Math.floor(numericLimit))
    : 30;

  const eventFilter = typeof opts.event === 'string' ? opts.event.trim().toUpperCase() : '';
  const outcomeFilter = typeof opts.outcome === 'string' ? opts.outcome.trim().toLowerCase() : '';

  const fetchSize = (eventFilter || outcomeFilter) ? Math.max(safeLimit * 4, 100) : safeLimit;
  const entries = readAuditEntries(fetchSize);

  const filtered = entries.filter((item) => {
    if (!item || typeof item !== 'object') return false;
    if (eventFilter && String(item.event || '').toUpperCase() !== eventFilter) {
      return false;
    }
    if (outcomeFilter && String(item.outcome || '').toLowerCase() !== outcomeFilter) {
      return false;
    }
    return true;
  });

  return filtered.slice(0, safeLimit);
}

module.exports = {
  recordAudit,
  listAuditLogs,
  maskIdentifier
};
