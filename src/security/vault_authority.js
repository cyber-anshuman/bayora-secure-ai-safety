/**
 * Bayora Vault Authority & Capability Token Service
 * Section J: Access Control (Capability Table) & Confused-Deputy Mitigation.
 * Issues short-lived, per-session, per-action tokens. Prevents token replay across sessions.
 */

const crypto = require('crypto');

class VaultAuthority {
  constructor(secretKey = 'BAYORA_VAULT_MASTER_SECRET') {
    this.secretKey = secretKey;
    this.activeTokens = new Map();
    this.revokedTokens = new Set();
  }

  /**
   * Issue a short-lived, action-scoped capability token for a specific tenant and session.
   * TTL: defaults to 300 seconds (5 mins).
   */
  issueToken({ tenantId, sessionId, allowedActions, ttlSeconds = 300 }) {
    if (!tenantId || !sessionId || !allowedActions) {
      throw new Error('Missing required token parameters: tenantId, sessionId, allowedActions');
    }

    const tokenId = `tok_${crypto.randomBytes(12).toString('hex')}`;
    const issuedAt = Date.now();
    const expiresAt = issuedAt + (ttlSeconds * 1000);

    const payload = {
      tokenId,
      tenantId,
      sessionId,
      allowedActions,
      issuedAt,
      expiresAt
    };

    const signature = this._sign(payload);
    const token = { ...payload, signature };

    this.activeTokens.set(tokenId, token);
    return token;
  }

  _sign(payload) {
    const data = `${payload.tokenId}:${payload.tenantId}:${payload.sessionId}:${payload.allowedActions.sort().join(',')}:${payload.expiresAt}`;
    return crypto.createHmac('sha256', this.secretKey).update(data).digest('hex');
  }

  /**
   * Validate token and check capability for a specific action and session.
   */
  validateCapability(token, requiredAction, targetSessionId) {
    if (!token || !token.tokenId) {
      return { valid: false, reason: 'TOKEN_MISSING' };
    }

    if (this.revokedTokens.has(token.tokenId)) {
      return { valid: false, reason: 'TOKEN_REVOKED' };
    }

    const expectedSignature = this._sign(token);
    if (token.signature !== expectedSignature) {
      return { valid: false, reason: 'INVALID_SIGNATURE' };
    }

    if (Date.now() > token.expiresAt) {
      return { valid: false, reason: 'TOKEN_EXPIRED' };
    }

    if (targetSessionId && token.sessionId !== targetSessionId) {
      return { valid: false, reason: 'SESSION_MISMATCH: Cross-session token replay prohibited' };
    }

    if (!token.allowedActions.includes(requiredAction) && !token.allowedActions.includes('*')) {
      return { valid: false, reason: `UNAUTHORIZED_CAPABILITY: Missing required action '${requiredAction}'` };
    }

    return { valid: true, tenantId: token.tenantId, sessionId: token.sessionId };
  }

  revokeToken(tokenId) {
    this.revokedTokens.add(tokenId);
    this.activeTokens.delete(tokenId);
  }
}

module.exports = VaultAuthority;
