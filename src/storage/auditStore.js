const fs = require('fs');
const path = require('path');
const config = require('../config/env');

const MAX_MEMORY_LOGS = 200;
const memoryLogs = [];
const logFilePath = path.join(__dirname, '..', '..', 'logs', 'audit.log');

let pgPool = null;
let pgUnavailable = false;

function getPgPool() {
  if (!config.databaseUrl || pgUnavailable) return null;
  if (pgPool) return pgPool;

  try {
    const { Pool } = require('pg');
    pgPool = new Pool({ connectionString: config.databaseUrl });
    pgPool.on('error', () => {
      pgUnavailable = true;
    });
    return pgPool;
  } catch (_) {
    pgUnavailable = true;
    return null;
  }
}

function appendAuditEntry(entry) {
  memoryLogs.unshift(entry);
  if (memoryLogs.length > MAX_MEMORY_LOGS) {
    memoryLogs.pop();
  }

  try {
    fs.mkdirSync(path.dirname(logFilePath), { recursive: true });
    fs.appendFileSync(logFilePath, JSON.stringify(entry) + '\n', 'utf8');
  } catch (_) {
    // Ignore les erreurs d'ecriture disque en environnement restreint
  }
}

async function persistAuditEntryToPg(entry) {
  const pool = getPgPool();
  if (!pool || !entry) return false;

  const queryText = `
    INSERT INTO audit_logs (event_time, event_type, identifier_masked, outcome, details)
    VALUES ($1, $2, $3, $4, $5)
  `;
  const values = [
    entry.eventTime || entry.event_time || new Date().toISOString(),
    entry.eventType || entry.event_type || 'UNKNOWN',
    entry.identifierMasked || entry.identifier_masked || 'masked',
    entry.outcome || 'info',
    entry.details || null
  ];

  try {
    await pool.query(queryText, values);
    return true;
  } catch (_) {
    return false;
  }
}

function readAuditEntries(limit = 30) {
  const parsed = Number.parseInt(limit, 10);
  const safeLimit = Number.isFinite(parsed) && parsed > 0 ? Math.min(parsed, MAX_MEMORY_LOGS) : 30;
  return memoryLogs.slice(0, safeLimit);
}

module.exports = {
  appendAuditEntry,
  persistAuditEntryToPg,
  readAuditEntries
};
