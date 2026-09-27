/**
 * Bayora Architecture Platform - Express REST Server
 * Provides full API for interactive dashboard, state machine execution,
 * WORM audit inspection, and live attack simulation lab.
 */

const express = require('express');
const path = require('path');
const WormAuditStore = require('./audit/worm_store');
const OpaPolicyEngine = require('./policy/opa_pdp');
const VaultAuthority = require('./security/vault_authority');
const BrokerStateMachine = require('./broker/state_machine');
const { RedSandbox, BlueSandbox } = require('./sandboxes/tenant_sandboxes');
const AttackSimulationSuite = require('./attacks/simulation_suite');
const sideChannelMitigations = require('./sidechannel/mitigations');
const benchmarkRegistry = require('./datasets/benchmark_registry');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const NODE_ENV = process.env.NODE_ENV || 'development';

app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Core Platform State
let auditStore = new WormAuditStore();
let opaPdp = new OpaPolicyEngine();
let vaultAuthority = new VaultAuthority();
let broker = new BrokerStateMachine(auditStore, opaPdp, vaultAuthority);
let redSandbox = new RedSandbox(broker, auditStore, opaPdp, vaultAuthority);
let blueSandbox = new BlueSandbox(broker, auditStore, opaPdp, vaultAuthority);
let simulationSuite = new AttackSimulationSuite();

// Helper to reset platform to clean state
function resetPlatform() {
  auditStore = new WormAuditStore();
  opaPdp = new OpaPolicyEngine();
  vaultAuthority = new VaultAuthority();
  broker = new BrokerStateMachine(auditStore, opaPdp, vaultAuthority);
  redSandbox = new RedSandbox(broker, auditStore, opaPdp, vaultAuthority);
  blueSandbox = new BlueSandbox(broker, auditStore, opaPdp, vaultAuthority);
  simulationSuite = new AttackSimulationSuite();
}

// -------------------------------------------------------------
// System Health & Topology API
// -------------------------------------------------------------
app.get('/api/status', (req, res) => {
  const auditReport = auditStore.verifyIntegrity();
  res.json({
    status: 'HEALTHY',
    version: '2.0.0-redteam-redesign',
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

// Create new session (SETUP)
app.post('/api/sessions', async (req, res) => {
  try {
    const { disclosurePolicy } = req.body;
    const sessionData = await broker.createSession(disclosurePolicy || 'REDACTED_DEFENSE');
    res.json(sessionData);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Submit Red Attack Payload (RED_TURN -> MODEL_INFERENCE -> EVAL)
app.post('/api/sessions/:id/red-turn', async (req, res) => {
  try {
    const { payloadText, token } = req.body;
    const sessionId = req.params.id;

    const result = await redSandbox.submitAttack(sessionId, payloadText, token);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message, canonical: sideChannelMitigations.toCanonicalError(err) });
  }
});

// Submit Blue Defensive Evaluation (BLUE_TURN -> CONCLUDE)
app.post('/api/sessions/:id/blue-turn', async (req, res) => {
  try {
    const { modelOutput, token } = req.body;
    const sessionId = req.params.id;

    const result = await blueSandbox.evaluateDefense(sessionId, modelOutput, token);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message, canonical: sideChannelMitigations.toCanonicalError(err) });
  }
});

// Retrieve Post-Conclude Disclosure Bundle (CONCLUDE -> DISCLOSURE)
app.get('/api/sessions/:id/disclosure', async (req, res) => {
  try {
    const sessionId = req.params.id;
    const tokenHeader = req.headers['authorization'];
    let token = null;

    if (tokenHeader) {
      try { token = JSON.parse(tokenHeader); } catch (e) { /* ignore */ }
    }

    // Fallback to active session blue token if client UI
    const session = broker.sessions.get(sessionId);
    if (!token && session) {
      token = session.tokens.blueToken;
    }

    const bundle = await broker.getDisclosureBundle(sessionId, token);
    res.json(bundle);
  } catch (err) {
    res.status(403).json({ error: err.message, canonical: sideChannelMitigations.toCanonicalError(err) });
  }
});

// Premature Red Payload Query Attempt (Test Information Flow)
app.get('/api/sessions/:id/red-payload-query', (req, res) => {
  try {
    const sessionId = req.params.id;
    const tokenHeader = req.headers['authorization'];
    let token = null;
    if (tokenHeader) {
      try { token = JSON.parse(tokenHeader); } catch (e) { /* ignore */ }
    }
    const result = broker.queryRedPayload(sessionId, token);
    res.json(result);
  } catch (err) {
    res.status(403).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// WORM Audit & Cryptographic Provenance API
// -------------------------------------------------------------

// Query audit trail (Auditor or Broker only)
app.get('/api/audit', (req, res) => {
  const role = req.query.role || 'auditor';
  const sessionId = req.query.sessionId;

  try {
    const records = auditStore.query(role, { sessionId });
    res.json({
      records,
      totalCount: records.length,
      merkleRoot: auditStore.getMerkleRoot(),
      anchors: auditStore.anchors
    });
  } catch (err) {
    res.status(403).json({ error: err.message, code: 'E_AUDIT_WRITE_ONLY' });
  }
});

// Check cryptographic integrity of audit chain
app.get('/api/audit/integrity', (req, res) => {
  const report = auditStore.verifyIntegrity();
  res.json({
    ...report,
    currentMerkleRoot: auditStore.getMerkleRoot(),
    anchoredRoot: auditStore.anchors.length > 0 ? auditStore.anchors[auditStore.anchors.length - 1].merkleRoot : null
  });
});

// Simulate tampering with an audit block (Demonstrate tamper-evidence)
app.post('/api/audit/tamper', (req, res) => {
  try {
    const { blockIndex, field, newValue } = req.body;
    const result = auditStore.simulateTamper(
      parseInt(blockIndex, 10) || 1,
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
app.post('/api/platform/reset', (req, res) => {
  resetPlatform();
  res.json({ status: 'RESET_OK', message: 'Platform environment and audit store re-initialized.' });
});

// -------------------------------------------------------------
// Attack Simulation Lab & PoC Verification API
// -------------------------------------------------------------

// Run all 9 PoC demonstration tests
app.get('/api/poc-tests', async (req, res) => {
  try {
    const results = await simulationSuite.runAllPocTests();
    res.json({ results, allPassed: results.every(r => r.passed) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// Run all 7 Attack Simulations
app.get('/api/attack-sims', async (req, res) => {
  try {
    const results = await simulationSuite.runAllAttackSimulations();
    res.json({ results, allMitigated: results.every(r => r.mitigationCertified) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Run a single specific attack simulation
app.post('/api/attack-sims/:id/run', async (req, res) => {
  const simId = req.params.id;
  try {
    let result = null;
    switch (simId) {
      case 'sim-1':
        result = await simulationSuite.runAttackSim1_RedSandboxEscape();
        break;
      case 'sim-2':
        result = await simulationSuite.runAttackSim2_TimingSideChannel();
        break;
      case 'sim-3':
        result = await simulationSuite.runAttackSim3_KvCacheProbe();
        break;
      case 'sim-4':
        result = await simulationSuite.runAttackSim4_ConfusedDeputy();
        break;
      case 'sim-5':
        result = await simulationSuite.runAttackSim5_AuditTamper();
        break;
      case 'sim-6':
        result = await simulationSuite.runAttackSim6_CanaryContamination();
        break;
      case 'sim-7':
        result = await simulationSuite.runAttackSim7_FaultInjection();
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
app.get('/api/metrics/:tenant', (req, res) => {
  const tenant = req.params.tenant;
  if (tenant !== 'red' && tenant !== 'blue' && tenant !== 'admin') {
    return res.status(400).json({ error: 'Invalid tenant identifier' });
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

app.listen(PORT, HOST, () => {
  console.log(`================================================================`);
  console.log(` BAYORA SECURE AI SAFETY TESTING PLATFORM (v2.0 Redesign)`);
  console.log(` Server active on http://${HOST}:${PORT} (${NODE_ENV})`);
  console.log(` Implementation of: bayora-redteam-review.md`);
  console.log(`================================================================`);
});
