const fs = require('fs');
const path = require('path');

const MAX_MEMORY_LOGS = 200;
const memoryLogs = [];
const logFilePath = path.join(__dirname, '..', '..', 'logs', 'audit.log');

function appendAuditEntry(entry) {
  memoryLogs.unshift(entry);
  if (memoryLogs.length > MAX_MEMORY_LOGS) {
    memoryLogs.pop();
  }

  try {
    fs.appendFileSync(logFilePath, JSON.stringify(entry) + '\n', 'utf8');
  } catch (_) {
    // Ignore les erreurs d'ecriture disque en environnement restreint
  }
}

function readAuditEntries(limit = 30) {
  const parsed = Number.parseInt(limit, 10);
  const safeLimit = Number.isFinite(parsed) && parsed > 0 ? Math.min(parsed, MAX_MEMORY_LOGS) : 30;
  return memoryLogs.slice(0, safeLimit);
}

module.exports = {
  appendAuditEntry,
  readAuditEntries
};
