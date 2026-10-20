/**
 * Bayora Architecture Platform - Express REST Server
 * Provides full API for interactive dashboard, state machine execution,
 * WORM audit inspection, and live attack simulation lab.
 */

const express = require('express');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const WormAuditStore = require('./audit/worm_store');
const OpaPolicyEngine = require('./policy/opa_pdp');
const VaultAuthority = require('./security/vault_authority');
const BrokerStateMachine = require('./broker/state_machine');
const { RedSandbox, BlueSandbox } = require('./sandboxes/tenant_sandboxes');
const AttackSimulationSuite = require('./attacks/simulation_suite');
const sideChannelMitigations = require('./sidechannel/mitigations');
const benchmarkRegistry = require('./datasets/benchmark_registry');
const {
  authenticate,
  requireAuth,
  requireRole,
  demoEndpointGate
} = require('./security/auth');
const pkg = require('../package.json');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';
const NODE_ENV = process.env.NODE_ENV || 'development';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"]
    }
  }
}));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX) || (process.env.NODE_ENV === 'test' ? 1000 : 60),
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

app.use(express.json({ limit: '32kb' }));
app.use(authenticate);
app.use(express.static(path.join(__dirname, '../public')));

// Core Platform State
let auditStore = new WormAuditStore();
let opaPdp = new OpaPolicyEngine();
let vaultAuthority = new VaultAuthority();
let broker = new BrokerStateMachine(auditStore, opaPdp, vaultAuthority);
let redSandbox = new RedSandbox(broker, auditStore, opaPdp, vaultAuthority);
let blueSandbox = new BlueSandbox(broker, auditStore, opaPdp, vaultAuthority);

let lastIntegrityCheckTime = 0;
let cachedAuditReport = null;
function getCachedIntegrityReport() {
  const now = Date.now();
  if (!cachedAuditReport || (now - lastIntegrityCheckTime) > 5000) {
    cachedAuditReport = auditStore.verifyIntegrity();
    lastIntegrityCheckTime = now;
  }
  return cachedAuditReport;
}

// Helper to reset platform to clean state
function resetPlatform() {
  cachedAuditReport = null;
  lastIntegrityCheckTime = 0;
  auditStore = new WormAuditStore();
  opaPdp = new OpaPolicyEngine();
  vaultAuthority = new VaultAuthority();
  broker = new BrokerStateMachine(auditStore, opaPdp, vaultAuthority);
  redSandbox = new RedSandbox(broker, auditStore, opaPdp, vaultAuthority);
  blueSandbox = new BlueSandbox(broker, auditStore, opaPdp, vaultAuthority);
}

// -------------------------------------------------------------
// System Health & Topology API
// -------------------------------------------------------------
app.get('/api/status', (req, res) => {
  const auditReport = getCachedIntegrityReport();
  res.json({
    status: auditStore.degraded ? 'DEGRADED' : (auditReport.isValid ? 'HEALTHY' : 'COMPROMISED'),
    degradedReason: auditStore.degraded ? auditStore.degradedReason : undefined,
    version: pkg.version,
    isolationTier: 'Kata Containers microVM (Target Architecture — modeled in PoC)',
    mandatoryMediation: 'ENABLED',
    activeSessions: broker.sessions.size,
    auditChainLength: auditStore.chain.length,
    auditChainValid: auditReport.isValid,
    latestMerkleRoot: auditStore.getMerkleRoot(),
    cniPolicy: 'Cilium eBPF Default-Deny (Target Architecture — modeled in PoC)',
    runtimeIsolation: 'Node.js worker_threads with V8 resourceLimits (Enforced in PoC)',
    nodeAntiAffinity: {
      red: sideChannelMitigations.getIsolatedNodeAssignment('red'),
      blue: sideChannelMitigations.getIsolatedNodeAssignment('blue'),
      model: sideChannelMitigations.getIsolatedNodeAssignment('model')
    }
  });
});

// -------------------------------------------------------------
// Session Lifecycle & State Machine API
// -------------------------------------------------------------

// Helper to extract capability token from request (header only)
function extractCapabilityToken(req) {
  const tokenHeader = req.headers['authorization'] || req.headers['x-capability-token'];
  if (tokenHeader) {
    try {
      const clean = typeof tokenHeader === 'string' && tokenHeader.startsWith('Bearer ')
        ? tokenHeader.slice(7)
        : tokenHeader;
      return JSON.parse(clean);
    } catch (e) {
      return { tokenId: tokenHeader };
    }
  }
  return null;
}

// Create new session (SETUP) - Admin or Broker only, returns only sessionId
app.post('/api/sessions', requireRole('admin', 'broker'), async (req, res) => {
  try {
    const { disclosurePolicy } = req.body || {};
    const policy = disclosurePolicy || 'REDACTED_DEFENSE';
    const ALLOWED_POLICIES = ['REDACTED_DEFENSE', 'FULL_BENCHMARK', 'COARSE_STATUS'];

    if (!ALLOWED_POLICIES.includes(policy)) {
      return res.status(400).json({
        error: `Invalid disclosure policy '${policy}'. Allowed: ${ALLOWED_POLICIES.join(', ')}`,
        code: 'E_INVALID_DISCLOSURE_POLICY'
      });
    }

    if (policy === 'FULL_BENCHMARK' && req.role !== 'admin' && req.role !== 'broker') {
      return res.status(403).json({
        error: "Forbidden: Only admin or broker role may select 'FULL_BENCHMARK' disclosure policy",
        code: 'E_FORBIDDEN'
      });
    }

    const sessionData = await broker.createSession(policy, req.role);
    res.json({ sessionId: sessionData.sessionId });
  } catch (err) {
    const status = err.statusCode || 500;
    res.status(status).json({ error: err.message, code: err.code });
  }
});

// Canonical error responder collapsing status codes to 403 and body to { code, message }
async function sendCanonicalError(res, err, startHrTime = null) {
  if (startHrTime) {
    await sideChannelMitigations.delayUntilNextBucket(startHrTime);
  }
  console.error('[API Error]:', err);
  const canonical = sideChannelMitigations.toCanonicalError(err);
  return res.status(403).json({
    code: canonical.code,
    message: canonical.message
  });
}

// Retrieve caller-specific capability token for a session
app.post('/api/sessions/:id/token', requireAuth, async (req, res) => {
  const sessionId = req.params.id;
  const session = broker.sessions.get(sessionId);
  if (!session) {
    return await sendCanonicalError(res, new Error('E_SESSION_NOT_FOUND'));
  }

  if (req.role === 'red') {
    return res.json({ token: session.tokens.redToken, role: 'red' });
  }
  if (req.role === 'blue') {
    return res.json({ token: session.tokens.blueToken, role: 'blue' });
  }
  if (req.role === 'admin') {
    const requestedTenant = (req.body && req.body.tenant) || req.query.tenant;
    if (requestedTenant === 'red') {
      return res.json({ token: session.tokens.redToken, role: 'red' });
    }
    if (requestedTenant === 'blue') {
      return res.json({ token: session.tokens.blueToken, role: 'blue' });
    }
    return res.json({
      redToken: session.tokens.redToken,
      blueToken: session.tokens.blueToken
    });
  }

  return await sendCanonicalError(res, new Error('E_FORBIDDEN'));
});

// Submit Red Attack Payload (RED_TURN -> MODEL_INFERENCE -> EVAL)
// Quantized monotonic timing delay and canonical error handling
app.post('/api/sessions/:id/red-turn', requireRole('red', 'admin'), async (req, res) => {
  const startHrTime = process.hrtime.bigint();
  try {
    const token = extractCapabilityToken(req) || (req.body && req.body.token);
    const { payloadText } = req.body || {};
    const sessionId = req.params.id;

    const result = await redSandbox.submitAttack(sessionId, payloadText, token);
    await sideChannelMitigations.delayUntilNextBucket(startHrTime);
    res.json({ sessionId: result.sessionId || sessionId, phase: 'ACCEPTED' });
  } catch (err) {
    await sendCanonicalError(res, err, startHrTime);
  }
});

// Coarse pass/fail status for Red after CONCLUDE
app.get('/api/sessions/:id/coarse-status', requireRole('red', 'admin'), async (req, res) => {
  const startHrTime = process.hrtime.bigint();
  try {
    const sessionId = req.params.id;
    const token = extractCapabilityToken(req) || (req.body && req.body.token);

    if (!token) {
      const err = new Error('Vault Deny: TOKEN_MISSING');
      err.code = 'E_AUTH_FAILED';
      return await sendCanonicalError(res, err, startHrTime);
    }

    // Check capability token BEFORE phase check
    const capCheck = vaultAuthority.validateCapability(token, 'read_coarse_status', sessionId, req.role === 'admin' ? null : 'red');
    if (!capCheck.valid) {
      const err = new Error(`Vault Deny: ${capCheck.reason}`);
      err.code = 'E_AUTH_FAILED';
      return await sendCanonicalError(res, err, startHrTime);
    }

    const session = broker.sessions.get(sessionId);
    if (!session) {
      return await sendCanonicalError(res, new Error('E_SESSION_NOT_FOUND'), startHrTime);
    }

    if (session.phase !== 'CONCLUDE' && session.phase !== 'DISCLOSURE') {
      const err = new Error(`State Machine Error: Cannot query coarse status in phase '${session.phase}'`);
      err.code = 'E_STATE_MACHINE_ERROR';
      return await sendCanonicalError(res, err, startHrTime);
    }

    // Consumed only on success
    vaultAuthority.consumeAction(token, 'read_coarse_status');

    const passed = session.modelResponse ? !session.modelResponse.isJailbreak : true;
    await sideChannelMitigations.delayUntilNextBucket(startHrTime);
    res.json({
      sessionId,
      phase: session.phase,
      status: passed ? 'PASS' : 'FAIL'
    });
  } catch (err) {
    await sendCanonicalError(res, err, startHrTime);
  }
});

// Model output endpoint for Blue in BLUE_TURN phase
app.get('/api/sessions/:id/model-output', requireRole('blue', 'admin'), async (req, res) => {
  const startHrTime = process.hrtime.bigint();
  try {
    const sessionId = req.params.id;
    const result = broker.getModelOutput(sessionId);
    await sideChannelMitigations.delayUntilNextBucket(startHrTime);
    res.json(result);
  } catch (err) {
    await sendCanonicalError(res, err, startHrTime);
  }
});

// Submit Blue Defensive Evaluation (BLUE_TURN -> CONCLUDE)
// Discards any client-supplied modelOutput; defense runs on real broker output
app.post('/api/sessions/:id/blue-turn', requireRole('blue', 'admin'), async (req, res) => {
  const startHrTime = process.hrtime.bigint();
  try {
    const token = extractCapabilityToken(req) || (req.body && req.body.token);
    const { ...params } = req.body || {};
    const sessionId = req.params.id;

    const result = await blueSandbox.evaluateDefense(sessionId, params, token);
    await sideChannelMitigations.delayUntilNextBucket(startHrTime);
    res.json(result);
  } catch (err) {
    await sendCanonicalError(res, err, startHrTime);
  }
});

// Retrieve Post-Conclude Disclosure Bundle (CONCLUDE -> DISCLOSURE)
app.get('/api/sessions/:id/disclosure', requireRole('blue', 'admin'), async (req, res) => {
  const startHrTime = process.hrtime.bigint();
  try {
    const sessionId = req.params.id;
    const token = extractCapabilityToken(req);

    if (!token) {
      const err = new Error('Vault Deny: TOKEN_MISSING');
      err.code = 'E_AUTH_FAILED';
      return await sendCanonicalError(res, err, startHrTime);
    }

    const bundle = await broker.getDisclosureBundle(sessionId, token);
    await sideChannelMitigations.delayUntilNextBucket(startHrTime);
    res.json(bundle);
  } catch (err) {
    await sendCanonicalError(res, err, startHrTime);
  }
});

// Red Payload Query Attempt (Information Flow Check)
app.get('/api/sessions/:id/red-payload-query', requireRole('blue', 'admin'), async (req, res) => {
  const startHrTime = process.hrtime.bigint();
  try {
    const sessionId = req.params.id;
    const token = extractCapabilityToken(req);

    if (!token) {
      const err = new Error('Vault Deny: TOKEN_MISSING');
      err.code = 'E_AUTH_FAILED';
      return await sendCanonicalError(res, err, startHrTime);
    }

    const result = broker.queryRedPayload(sessionId, token);
    if (!result.allowed) {
      const err = new Error(result.reason || 'Query denied');
      err.code = result.code || 'E_POLICY_DENIED';
      return await sendCanonicalError(res, err, startHrTime);
    }

    await sideChannelMitigations.delayUntilNextBucket(startHrTime);
    res.json(result);
  } catch (err) {
    await sendCanonicalError(res, err, startHrTime);
  }
});

// -------------------------------------------------------------
// WORM Audit & Cryptographic Provenance API
// -------------------------------------------------------------

// Query audit trail (Auditor only)
app.get('/api/audit', requireRole('auditor', 'admin'), (req, res) => {
  const role = req.role;
  const sessionId = req.query.sessionId;
  const limit = Math.min(1000, Math.max(1, parseInt(req.query.limit, 10) || 200));
  const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);

  try {
    const allRecords = auditStore.query(role, { sessionId });
    const pagedRecords = allRecords.slice(offset, offset + limit);
    const latestAnchor = auditStore.anchors.length > 0 ? auditStore.anchors[auditStore.anchors.length - 1] : null;
    res.json({
      records: pagedRecords,
      totalCount: allRecords.length,
      limit,
      offset,
      merkleRoot: auditStore.getMerkleRoot(),
      latestAnchor,
      anchorCount: auditStore.anchors.length
    });
  } catch (err) {
    res.status(403).json({ error: err.message, code: 'E_AUDIT_WRITE_ONLY' });
  }
});

// Check cryptographic integrity of audit chain (Auditor only)
app.get('/api/audit/integrity', requireRole('auditor', 'admin'), async (req, res) => {
  const report = await auditStore.verifyIntegrityAsync();
  const latestAnchor = auditStore.anchors.length > 0 ? auditStore.anchors[auditStore.anchors.length - 1] : null;
  res.json({
    ...report,
    currentMerkleRoot: auditStore.getMerkleRoot(),
    anchoredRoot: latestAnchor ? latestAnchor.merkleRoot : null
  });
});

// Simulate tampering with an audit block (Demonstrate tamper-evidence)
app.post('/api/audit/tamper', demoEndpointGate, (req, res) => {
  try {
    const { blockIndex, field, newValue } = req.body;
    const idx = (blockIndex !== undefined && blockIndex !== null) ? parseInt(blockIndex, 10) : 1;
    const result = auditStore.simulateTamper(
      idx,
      field || 'eventType',
      newValue || 'MALICIOUS_TAMPERED_RECORD'
    );
    const integrityAfter = auditStore.verifyIntegrity();
    res.json({
      tamperResult: result,
      integrityAfter
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Reset platform to clean state
app.post('/api/platform/reset', demoEndpointGate, (req, res) => {
  resetPlatform();
  res.json({ status: 'RESET_OK', message: 'Platform environment and audit store re-initialized.' });
});

// -------------------------------------------------------------
// Attack Simulation Lab & PoC Verification API
// -------------------------------------------------------------

// Run all 9 PoC demonstration tests
app.get('/api/poc-tests', demoEndpointGate, async (req, res) => {
  try {
    const suite = new AttackSimulationSuite();
    const results = await suite.runAllPocTests();
    res.json({ results, allPassed: results.every(r => r.passed) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Run all 7 Attack Simulations
app.get('/api/attack-sims', demoEndpointGate, async (req, res) => {
  try {
    const suite = new AttackSimulationSuite();
    const results = await suite.runAllAttackSimulations();
    res.json({ results, allMitigated: results.every(r => r.mitigationCertified) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Run a single specific attack simulation
app.post('/api/attack-sims/:id/run', demoEndpointGate, async (req, res) => {
  const simId = req.params.id;
  try {
    const suite = new AttackSimulationSuite();
    let result = null;
    switch (simId) {
      case 'sim-1':
        result = await suite.runAttackSim1_RedSandboxEscape();
        break;
      case 'sim-2':
        result = await suite.runAttackSim2_TimingSideChannel();
        break;
      case 'sim-3':
        result = await suite.runAttackSim3_KvCacheProbe();
        break;
      case 'sim-4':
        result = await suite.runAttackSim4_ConfusedDeputy();
        break;
      case 'sim-5':
        result = await suite.runAttackSim5_AuditTamper();
        break;
      case 'sim-6':
        result = await suite.runAttackSim6_CanaryContamination();
        break;
      case 'sim-7':
        result = await suite.runAttackSim7_FaultInjection();
        break;
      default:
        return res.status(404).json({ error: `Unknown simulation ID: ${simId}` });
    }
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// Observability & Telemetry API
// -------------------------------------------------------------
app.get('/api/metrics/:tenant', requireAuth, (req, res) => {
  const tenant = req.params.tenant;
  if (tenant !== 'red' && tenant !== 'blue' && tenant !== 'admin') {
    return res.status(400).json({ error: 'Invalid tenant identifier' });
  }

  if (req.role !== 'admin' && req.role !== tenant) {
    return res.status(403).json({
      error: `Forbidden: Tenant '${req.role}' cannot access metrics for '${tenant}'`,
      code: 'E_FORBIDDEN'
    });
  }

  // Simulated metrics bucketed into 10% ranges
  const rawCpu = tenant === 'red' ? 44.2 : 31.8;
  const rawMem = tenant === 'red' ? 62.5 : 54.1;

  res.json({
    tenant,
    scopedNamespace: `bayora-tenant-${tenant}`,
    cpuUsage: sideChannelMitigations.bucketMetric(rawCpu),
    memoryUsage: sideChannelMitigations.bucketMetric(rawMem),
    nodeBinding: sideChannelMitigations.getIsolatedNodeAssignment(tenant),
    visiblePeers: [] // Strict isolation: cannot see other tenants' metrics
  });
});

// -------------------------------------------------------------
// Benchmark & Dataset Registry API
// -------------------------------------------------------------
app.get('/api/datasets', (req, res) => {
  res.json({
    totalDatasets: 8,
    datasets: benchmarkRegistry.getDatasetList()
  });
});

app.get('/api/datasets/samples', (req, res) => {
  res.json({
    samples: benchmarkRegistry.getAllSamples()
  });
});

app.get('/api/datasets/:id', (req, res) => {
  const dataset = benchmarkRegistry.getDataset(req.params.id);
  if (!dataset) {
    return res.status(404).json({ error: `Dataset '${req.params.id}' not found` });
  }
  res.json(dataset);
});

if (require.main === module) {
  app.listen(PORT, HOST, () => {
    console.log(`================================================================`);
    console.log(` BAYORA SECURE AI SAFETY TESTING PLATFORM (v2.0 Redesign)`);
    console.log(` Server active on http://${HOST}:${PORT} (${NODE_ENV})`);
    console.log(` Implementation of: bayora-redteam-review.md`);
    console.log(`================================================================`);
  });
}

module.exports = app;
