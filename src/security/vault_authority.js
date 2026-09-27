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
    this.defaultTtlMs = Number(process.env.VAULT_TOKEN_TTL_MS) || 60000;
    this.allowRefresh = process.env.VAULT_ALLOW_REFRESH === 'true';
  }

  /**
   * Issue a short-lived, action-scoped capability token for a specific tenant and session.
   * TTL: defaults to VAULT_TOKEN_TTL_MS (or 60s / custom ttlSeconds).
   */
  issueToken({ tenantId, sessionId, allowedActions, ttlSeconds = undefined }) {
    if (!tenantId || !sessionId || !allowedActions) {
      throw new Error('Missing required token parameters: tenantId, sessionId, allowedActions');
    }

    const tokenId = `tok_${crypto.randomBytes(12).toString('hex')}`;
    const issuedAt = Date.now();
    const ttlMs = (ttlSeconds !== undefined && ttlSeconds !== null) ? (ttlSeconds * 1000) : this.defaultTtlMs;
    const expiresAt = issuedAt + ttlMs;

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
    const actions = Array.isArray(payload.allowedActions) ? [...payload.allowedActions].sort().join(',') : '';
    const data = `${payload.tokenId}:${payload.tenantId}:${payload.sessionId}:${actions}:${payload.expiresAt}`;
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

  /**
   * Refresh an active capability token if allowed by configuration (§J)
   */
  refreshToken(token) {
    if (!this.allowRefresh) {
      return { success: false, reason: 'E_REFRESH_DISABLED: Token refresh disallowed by configuration' };
    }
    const validation = this.validateCapability(token, token && token.allowedActions && token.allowedActions[0], token && token.sessionId);
    if (!validation.valid) {
      return { success: false, reason: validation.reason };
    }
    const refreshed = this.issueToken({
      tenantId: token.tenantId,
      sessionId: token.sessionId,
      allowedActions: token.allowedActions
    });
    return { success: true, token: refreshed };
  }

  revokeToken(tokenId) {
    this.revokedTokens.add(tokenId);
    this.activeTokens.delete(tokenId);
  }
}

module.exports = VaultAuthority;
