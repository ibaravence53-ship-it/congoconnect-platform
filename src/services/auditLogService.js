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

function listAuditLogs(limit = 30) {
  return readAuditEntries(limit);
}

module.exports = {
  recordAudit,
  listAuditLogs,
  maskIdentifier
};
