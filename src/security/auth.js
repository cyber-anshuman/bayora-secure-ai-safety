/**
 * Bayora Authentication & Role-Based Access Control
 * Enforces API key authentication using crypto.timingSafeEqual
 * Sets req.role for downstream authorization
 */

const crypto = require('crypto');

const REQUIRED_KEY_VARS = [
  'RED_API_KEY',
  'BLUE_API_KEY',
  'AUDITOR_API_KEY',
  'ADMIN_API_KEY'
];

const KNOWN_EXAMPLE_VALUES = new Set([
  'bayora_production_vault_secret_min_32_characters_long',
  'bayora_production_worm_secret_min_32_characters_long',
  'red_dev_key_example_secret_1234567890',
  'blue_dev_key_example_secret_1234567890',
  'auditor_dev_key_example_secret_1234567890',
  'admin_dev_key_example_secret_1234567890'
]);

let devKeysPrinted = false;

function validateProductionSecrets(env = process.env) {
  const nodeEnv = env.NODE_ENV || 'development';
  if (nodeEnv === 'production') {
    const secretsToCheck = [
      { name: 'VAULT_SECRET', val: env.VAULT_SECRET },
      { name: 'WORM_ANCHOR_SECRET', val: env.WORM_ANCHOR_SECRET || env.BAYORA_ANCHOR_SECRET },
      { name: 'RED_API_KEY', val: env.RED_API_KEY },
      { name: 'BLUE_API_KEY', val: env.BLUE_API_KEY },
      { name: 'AUDITOR_API_KEY', val: env.AUDITOR_API_KEY },
      { name: 'ADMIN_API_KEY', val: env.ADMIN_API_KEY }
    ];
    for (const { name, val } of secretsToCheck) {
      if (val && KNOWN_EXAMPLE_VALUES.has(val)) {
        throw new Error(`Refusing to start in production: Insecure known-example secret detected for ${name}. Generate a production secret using 'openssl rand -hex 32'.`);
      }
    }
  }
}

function ensureApiKeys() {
  const nodeEnv = process.env.NODE_ENV || 'development';

  if (nodeEnv !== 'development' && nodeEnv !== 'test') {
    const missing = REQUIRED_KEY_VARS.filter(k => !process.env[k]);
    if (missing.length > 0) {
      throw new Error(`Refusing to start: Missing required API keys in environment: ${missing.join(', ')}`);
    }
  } else {
    let generated = false;
    for (const keyVar of REQUIRED_KEY_VARS) {
      if (!process.env[keyVar]) {
        process.env[keyVar] = `dev_${keyVar.toLowerCase()}_${crypto.randomBytes(16).toString('hex')}`;
        generated = true;
      }
    }
    if (generated && !devKeysPrinted && nodeEnv === 'development') {
      devKeysPrinted = true;
      console.log('=== DEVELOPMENT API KEYS INITIALIZED ===');
      for (const keyVar of REQUIRED_KEY_VARS) {
        console.log(`  ${keyVar}: ${process.env[keyVar]}`);
      }
      console.log('========================================');
    }
  }

  validateProductionSecrets();
}

// Initialize on module load
ensureApiKeys();

function getApiKeys() {
  return {
    admin: process.env.ADMIN_API_KEY,
    broker: process.env.BROKER_API_KEY || process.env.ADMIN_API_KEY,
    auditor: process.env.AUDITOR_API_KEY,
    red: process.env.RED_API_KEY,
    blue: process.env.BLUE_API_KEY
  };
}

function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const hashA = crypto.createHash('sha256').update(a).digest();
  const hashB = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

function authenticate(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  req.role = null;

  if (apiKey && typeof apiKey === 'string') {
    const keys = getApiKeys();
    for (const [role, key] of Object.entries(keys)) {
      if (key && safeCompare(apiKey, key)) {
        req.role = role;
        break;
      }
    }
  }
  next();
}

function requireAuth(req, res, next) {
  if (!req.role) {
    return res.status(401).json({
      error: 'Authentication failed: Missing or invalid X-API-Key header',
      code: 'E_AUTH_FAILED'
    });
  }
  next();
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.role) {
      return res.status(401).json({
        error: 'Authentication failed: Missing or invalid X-API-Key header',
        code: 'E_AUTH_FAILED'
      });
    }

    const effectiveAllowed = [...allowedRoles];
    if (allowedRoles.includes('broker') && !effectiveAllowed.includes('admin')) {
      effectiveAllowed.push('admin');
    }

    if (!effectiveAllowed.includes(req.role)) {
      return res.status(403).json({
        error: `Forbidden: Role '${req.role}' is not authorized for this action`,
        code: 'E_FORBIDDEN'
      });
    }
    next();
  };
}

function demoEndpointGate(req, res, next) {
  if (process.env.ENABLE_DEMO_ENDPOINTS !== 'true') {
    return res.status(404).json({ error: 'Endpoint not found' });
  }

  if (!req.role) {
    return res.status(401).json({
      error: 'Authentication failed: Missing or invalid X-API-Key header',
      code: 'E_AUTH_FAILED'
    });
  }

  if (req.role !== 'admin') {
    return res.status(404).json({ error: 'Endpoint not found' });
  }

  next();
}

module.exports = {
  ensureApiKeys,
  getApiKeys,
  safeCompare,
  authenticate,
  requireAuth,
  requireRole,
  demoEndpointGate,
  validateProductionSecrets,
  KNOWN_EXAMPLE_VALUES
};
