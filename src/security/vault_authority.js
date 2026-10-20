/**
 * Bayora Vault Authority & Capability Token Service
 * Section J: Access Control (Capability Table) & Confused-Deputy Mitigation.
 * Issues short-lived, per-session, per-action tokens. Prevents token replay across sessions.
 */

const crypto = require('crypto');

class VaultAuthority {
  constructor(secretKey = null) {
    const envSecret = process.env.VAULT_SECRET;
    const nodeEnv = process.env.NODE_ENV || 'development';

    if (secretKey) {
      if (typeof secretKey !== 'string' || secretKey.length < 32) {
        throw new Error('VAULT_SECRET must be at least 32 characters');
      }
      this.secretKey = secretKey;
    } else if (envSecret) {
      if (typeof envSecret !== 'string' || envSecret.length < 32) {
        throw new Error('VAULT_SECRET must be at least 32 characters');
      }
      this.secretKey = envSecret;
    } else if (nodeEnv === 'development' || nodeEnv === 'test') {
      this.secretKey = crypto.randomBytes(32).toString('hex');
    } else {
      throw new Error('Refusing to start: VAULT_SECRET environment variable is required and must be at least 32 characters');
    }

    if (nodeEnv === 'production' && this.secretKey === 'bayora_production_vault_secret_min_32_characters_long') {
      throw new Error('Refusing to start in production: Insecure known-example secret detected for VAULT_SECRET. Generate a production secret using \'openssl rand -hex 32\'.');
    }

    this.activeTokens = new Map();
    this.revokedTokens = new Set();
    this.defaultTtlMs = Number(process.env.VAULT_TOKEN_TTL_MS) || (15 * 60 * 1000);
    this.maxLifetimeMs = Number(process.env.VAULT_MAX_LIFETIME_MS) || (60 * 60 * 1000);
    this.allowRefresh = process.env.VAULT_ALLOW_REFRESH === 'true';
  }

  /**
   * Issue a short-lived, action-scoped capability token for a specific tenant and session.
   */
  issueToken({ tenantId, sessionId, allowedActions, ttlSeconds = undefined, initialIssuedAt = undefined }) {
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
      expiresAt,
      initialIssuedAt: initialIssuedAt || issuedAt
    };

    const signature = this._sign(payload);
    const token = { ...payload, signature };

    this.activeTokens.set(tokenId, {
      ...token,
      consumedActions: new Set()
    });

    return token;
  }

  _sign(payload) {
    const actions = Array.isArray(payload.allowedActions) ? [...payload.allowedActions].sort().join(',') : '';
    const initial = payload.initialIssuedAt || payload.issuedAt || 0;
    const data = `${payload.tokenId}:${payload.tenantId}:${payload.sessionId}:${actions}:${payload.issuedAt}:${payload.expiresAt}:${initial}`;
    return crypto.createHmac('sha256', this.secretKey).update(data).digest('hex');
  }

  /**
   * Validate token and check capability for a specific action, session, and tenant.
   * activeTokens is the source of truth.
   */
  validateCapability(token, requiredAction, targetSessionId, expectedTenant = null) {
    if (!token || !token.tokenId) {
      return { valid: false, reason: 'TOKEN_MISSING' };
    }

    const active = this.activeTokens.get(token.tokenId);
    if (!active) {
      return { valid: false, reason: 'TOKEN_NOT_ACTIVE: Token is not active or has already been consumed' };
    }

    if (this.revokedTokens.has(token.tokenId)) {
      return { valid: false, reason: 'TOKEN_REVOKED' };
    }

    const expectedSignature = this._sign(token);
    const sigBuffer = Buffer.from(String(token.signature || ''), 'hex');
    const expectedBuffer = Buffer.from(expectedSignature, 'hex');

    if (sigBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
      return { valid: false, reason: 'INVALID_SIGNATURE' };
    }

    if (Date.now() > token.expiresAt) {
      this.activeTokens.delete(token.tokenId);
      return { valid: false, reason: 'TOKEN_EXPIRED' };
    }

    if (targetSessionId && token.sessionId !== targetSessionId) {
      return { valid: false, reason: 'SESSION_MISMATCH: Cross-session token replay prohibited' };
    }

    if (expectedTenant && token.tenantId !== expectedTenant) {
      return { valid: false, reason: `TENANT_MISMATCH: Token tenant '${token.tenantId}' does not match expected tenant '${expectedTenant}'` };
    }

    if (token.allowedActions.includes('*')) {
      return { valid: false, reason: 'WILDCARD_ACTION_PROHIBITED: Wildcard capability tokens are prohibited' };
    }

    if (!token.allowedActions.includes(requiredAction)) {
      return { valid: false, reason: `UNAUTHORIZED_CAPABILITY: Missing required action '${requiredAction}'` };
    }

    if (active.consumedActions && active.consumedActions.has(requiredAction)) {
      return { valid: false, reason: `ACTION_ALREADY_CONSUMED: Action '${requiredAction}' has already been consumed on this token` };
    }

    return { valid: true, tenantId: token.tenantId, sessionId: token.sessionId };
  }

  consumeAction(tokenOrId, action) {
    const tokenId = typeof tokenOrId === 'string' ? tokenOrId : tokenOrId?.tokenId;
    if (!tokenId) return false;

    const active = this.activeTokens.get(tokenId);
    if (!active) return false;

    if (!active.consumedActions) {
      active.consumedActions = new Set();
    }
    active.consumedActions.add(action);

    if (Array.isArray(active.allowedActions) && active.allowedActions.every(a => active.consumedActions.has(a))) {
      this.activeTokens.delete(tokenId);
    }
    return true;
  }

  markActionConsumed(tokenOrId, action) {
    return this.consumeAction(tokenOrId, action);
  }

  /**
   * Refresh an active capability token if allowed by configuration (§J)
   * Invalidate old token and enforce lifetime cap.
   */
  refreshToken(token) {
    if (!this.allowRefresh) {
      return { success: false, reason: 'E_REFRESH_DISABLED: Token refresh disallowed by configuration' };
    }

    const validation = this.validateCapability(
      token,
      token && token.allowedActions && token.allowedActions[0],
      token && token.sessionId,
      token && token.tenantId
    );
    if (!validation.valid) {
      return { success: false, reason: validation.reason };
    }

    const active = this.activeTokens.get(token.tokenId);
    const initialIssuedAt = (active && active.initialIssuedAt) || token.initialIssuedAt || token.issuedAt || Date.now();
    if (Date.now() - initialIssuedAt > this.maxLifetimeMs) {
      return { success: false, reason: 'E_MAX_LIFETIME_EXCEEDED: Token has exceeded VAULT_MAX_LIFETIME_MS' };
    }

    this.revokeToken(token.tokenId);

    const refreshed = this.issueToken({
      tenantId: token.tenantId,
      sessionId: token.sessionId,
      allowedActions: token.allowedActions,
      initialIssuedAt
    });

    return { success: true, token: refreshed };
  }

  revokeToken(tokenId) {
    this.revokedTokens.add(tokenId);
    this.activeTokens.delete(tokenId);
  }
}

module.exports = VaultAuthority;
