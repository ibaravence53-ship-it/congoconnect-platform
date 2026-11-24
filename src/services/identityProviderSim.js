function normalizeIdentifier(raw) {
  if (typeof raw !== 'string') return '';
  return raw.trim().replace(/[\s-]/g, '');
}

function isValidIdentifierFormat(identifier) {
  if (!identifier || identifier.length < 4 || identifier.length > 32) {
    return false;
  }
  return /^\+?[0-9]{7,15}$/.test(identifier) || /^[A-Za-z0-9_-]{4,32}$/.test(identifier);
}

function lookupIdentity(rawIdentifier) {
  const identifier = normalizeIdentifier(rawIdentifier);
  if (!isValidIdentifierFormat(identifier)) {
    return { ok: false, error: 'Format d identifiant invalide' };
  }

  return {
    ok: true,
    profile: {
      identifier,
      status: 'simulated_active',
      verifiedLevel: 'LOA-1',
      source: 'identityProviderSim'
    }
  };
}

module.exports = {
  lookupIdentity
};
