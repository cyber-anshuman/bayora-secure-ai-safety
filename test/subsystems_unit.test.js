/**
 * Bayora Subsystems Unit Test Suite
 * Tests edge cases, guard rails, state transitions, and error paths across:
 * - BrokerStateMachine (src/broker/state_machine.js)
 * - SideChannelMitigations (src/sidechannel/mitigations.js)
 * - VaultAuthority (src/security/vault_authority.js)
 */

const assert = require('assert');
const BrokerStateMachine = require('../src/broker/state_machine');
const sideChannelMitigations = require('../src/sidechannel/mitigations');
const VaultAuthority = require('../src/security/vault_authority');
const OpaPolicyEngine = require('../src/policy/opa_pdp');
const WormAuditStore = require('../src/audit/worm_store');
const EvaluationIntegrityEngine = require('../src/eval/integrity');

async function runSubsystemsUnitTests() {
  console.log('Running Subsystems Unit Tests (Branch Coverage & Guardrail Verification)...');

  // =========================================================================
  // 1. VaultAuthority Branch & Guardrail Tests
  // =========================================================================
  const vault = new VaultAuthority('TEST_VAULT_SECRET_KEY_123');

  // 1a. Missing token parameters in issueToken
  assert.throws(() => {
    vault.issueToken({ sessionId: 'sess_1', allowedActions: ['submit_attack'] });
  }, /Missing required token parameters/, 'issueToken must throw when tenantId is missing');

  assert.throws(() => {
    vault.issueToken({ tenantId: 'red', allowedActions: ['submit_attack'] });
  }, /Missing required token parameters/, 'issueToken must throw when sessionId is missing');

  assert.throws(() => {
    vault.issueToken({ tenantId: 'red', sessionId: 'sess_1' });
  }, /Missing required token parameters/, 'issueToken must throw when allowedActions is missing');

  // 1b. Validate capability: missing / invalid token object
  assert.deepStrictEqual(vault.validateCapability(null, 'submit_attack', 'sess_1'), {
    valid: false,
    reason: 'TOKEN_MISSING'
  });
  assert.deepStrictEqual(vault.validateCapability({}, 'submit_attack', 'sess_1'), {
    valid: false,
    reason: 'TOKEN_MISSING'
  });

  // 1c. Validate capability: revoked token
  const tokenToRevoke = vault.issueToken({
    tenantId: 'red',
    sessionId: 'sess_revoke_test',
    allowedActions: ['submit_attack']
  });
  vault.revokeToken(tokenToRevoke.tokenId);
  assert.deepStrictEqual(vault.validateCapability(tokenToRevoke, 'submit_attack', 'sess_revoke_test'), {
    valid: false,
    reason: 'TOKEN_REVOKED'
  });

  // 1d. Validate capability: invalid signature (tampered token)
  const validToken = vault.issueToken({
    tenantId: 'red',
    sessionId: 'sess_tamper_test',
    allowedActions: ['submit_attack']
  });
  const tamperedToken = { ...validToken, signature: 'deadbeef00112233' };
  assert.deepStrictEqual(vault.validateCapability(tamperedToken, 'submit_attack', 'sess_tamper_test'), {
    valid: false,
    reason: 'INVALID_SIGNATURE'
  });

  // 1e. Validate capability: expired token
  const expiredToken = {
    ...validToken,
    expiresAt: Date.now() - 5000,
    signature: ''
  };
  expiredToken.signature = vault._sign(expiredToken);
  assert.deepStrictEqual(vault.validateCapability(expiredToken, 'submit_attack', 'sess_tamper_test'), {
    valid: false,
    reason: 'TOKEN_EXPIRED'
  });

  // 1f. Validate capability: cross-session token replay
  assert.deepStrictEqual(vault.validateCapability(validToken, 'submit_attack', 'sess_DIFFERENT_TARGET'), {
    valid: false,
    reason: 'SESSION_MISMATCH: Cross-session token replay prohibited'
  });

  // 1g. Validate capability: unauthorized action
  assert.deepStrictEqual(vault.validateCapability(validToken, 'unauthorized_action', 'sess_tamper_test'), {
    valid: false,
    reason: "UNAUTHORIZED_CAPABILITY: Missing required action 'unauthorized_action'"
  });

  // 1h. Validate capability: wildcard permission '*'
  const wildcardToken = vault.issueToken({
    tenantId: 'admin',
    sessionId: 'sess_wildcard',
    allowedActions: ['*']
  });
  const wildCheck = vault.validateCapability(wildcardToken, 'any_action_allowed', 'sess_wildcard');
  assert.strictEqual(wildCheck.valid, true);

  console.log('✓ VaultAuthority branch tests passed cleanly.');

  // =========================================================================
  // 2. SideChannelMitigations Branch & Error Taxonomy Tests
  // =========================================================================
  // 2a. quantizeResponseTime edge cases (negative, zero, exact boundary)
  assert.strictEqual(sideChannelMitigations.quantizeResponseTime(0), 250);
  assert.strictEqual(sideChannelMitigations.quantizeResponseTime(-50), 250);
  assert.strictEqual(sideChannelMitigations.quantizeResponseTime(250), 250);
  assert.strictEqual(sideChannelMitigations.quantizeResponseTime(251), 500);

  // 2b. toCanonicalError mapping
  const authErr1 = sideChannelMitigations.toCanonicalError('INVALID_TOKEN_SUPPLIED');
  assert.strictEqual(authErr1.code, 'SEC_ERR_01');
  const authErr2 = sideChannelMitigations.toCanonicalError('SIGNATURE_MISMATCH');
  assert.strictEqual(authErr2.code, 'SEC_ERR_01');
  const authErr3 = sideChannelMitigations.toCanonicalError('CAPABILITY_DENIED');
  assert.strictEqual(authErr3.code, 'SEC_ERR_01');

  const policyErr1 = sideChannelMitigations.toCanonicalError('OPA Policy rejection');
  assert.strictEqual(policyErr1.code, 'SEC_ERR_02');
  const policyErr2 = sideChannelMitigations.toCanonicalError('DENY_RULE_TRIGGERED');
  assert.strictEqual(policyErr2.code, 'SEC_ERR_02');
  const policyErr3 = sideChannelMitigations.toCanonicalError('Information-Flow violation');
  assert.strictEqual(policyErr3.code, 'SEC_ERR_02');

  const timeoutErr1 = sideChannelMitigations.toCanonicalError('Worker timeout exceeded');
  assert.strictEqual(timeoutErr1.code, 'NET_ERR_01');
  const timeoutErr2 = sideChannelMitigations.toCanonicalError('Connection Timeout');
  assert.strictEqual(timeoutErr2.code, 'NET_ERR_01');

  const notFoundErr1 = sideChannelMitigations.toCanonicalError('Resource not found in cache');
  assert.strictEqual(notFoundErr1.code, 'RES_ERR_01');
  const notFoundErr2 = sideChannelMitigations.toCanonicalError('State mismatch in phase RED_TURN');
  assert.strictEqual(notFoundErr2.code, 'RES_ERR_01');

  const genericErr = sideChannelMitigations.toCanonicalError('Unknown unexpected exception');
  assert.strictEqual(genericErr.code, 'GEN_ERR_00');

  // 2c. bucketMetric (clamping and intervals)
  assert.deepStrictEqual(sideChannelMitigations.bucketMetric(-15), { band: '0% - 10%', coarseValue: 5 });
  assert.deepStrictEqual(sideChannelMitigations.bucketMetric(0), { band: '0% - 10%', coarseValue: 5 });
  assert.deepStrictEqual(sideChannelMitigations.bucketMetric(42), { band: '40% - 50%', coarseValue: 45 });
  assert.deepStrictEqual(sideChannelMitigations.bucketMetric(99), { band: '90% - 100%', coarseValue: 95 });
  assert.deepStrictEqual(sideChannelMitigations.bucketMetric(100), { band: '100% - 110%', coarseValue: 105 });
  assert.deepStrictEqual(sideChannelMitigations.bucketMetric(150), { band: '100% - 110%', coarseValue: 105 });

  // 2d. getIsolatedNodeAssignment default fallback
  const defaultAssignment = sideChannelMitigations.getIsolatedNodeAssignment('unknown_tenant_xyz');
  assert.strictEqual(defaultAssignment.node, 'node-default');
  assert.strictEqual(defaultAssignment.cpuset, '0');

  console.log('✓ SideChannelMitigations branch tests passed cleanly.');

  // =========================================================================
  // 3. BrokerStateMachine Guardrails & State Transition Rejection Tests
  // =========================================================================
  const audit = new WormAuditStore();
  const opa = new OpaPolicyEngine();
  const smVault = new VaultAuthority();
  const integrity = new EvaluationIntegrityEngine();
  const broker = new BrokerStateMachine(audit, opa, smVault, integrity);

  // 3a. getSession() branch tests (non-existent session returns null)
  assert.strictEqual(broker.getSession('non_existent_session_id'), null);

  // 3b. processRedTurn error paths
  await assert.rejects(
    broker.processRedTurn('missing_session', 'payload', {}),
    /E_SESSION_NOT_FOUND/,
    'processRedTurn must throw E_SESSION_NOT_FOUND on unknown session'
  );

  const sessionData1 = await broker.createSession('REDACTED_DEFENSE');
  const sess1Id = sessionData1.sessionId;

  // 3c. getSession() on valid active session
  const activeSessionInfo = broker.getSession(sess1Id);
  assert.strictEqual(activeSessionInfo.sessionId, sess1Id);
  assert.strictEqual(activeSessionInfo.phase, 'RED_TURN');

  // 3d. processBlueTurn when in RED_TURN (skipping a turn / illegal phase transition)
  await assert.rejects(
    broker.processBlueTurn(sess1Id, { isBlocked: false }, sessionData1.blueToken),
    /State Machine Error: Cannot process BLUE_TURN while in phase 'RED_TURN'/,
    'processBlueTurn must throw when called out of sequence'
  );

  // 3e. processRedTurn with invalid capability token
  const invalidToken = { tokenId: 'bad_token' };
  await assert.rejects(
    broker.processRedTurn(sess1Id, 'attack', invalidToken),
    /Vault Deny:/,
    'processRedTurn must reject with Vault Deny on invalid token'
  );

  // 3f. Complete Red turn legitimately -> advances to BLUE_TURN
  const redResult = await broker.processRedTurn(sess1Id, 'exploit_probe', sessionData1.redToken);
  assert.strictEqual(redResult.phase, 'BLUE_TURN');

  // 3g. Double-submitting Red turn when already in BLUE_TURN
  await assert.rejects(
    broker.processRedTurn(sess1Id, 'attack_again', sessionData1.redToken),
    /State Machine Error: Cannot process RED_TURN while in phase 'BLUE_TURN'/,
    'processRedTurn must reject double-submission'
  );

  // 3h. processBlueTurn error paths (missing session & invalid token)
  await assert.rejects(
    broker.processBlueTurn('missing_session', { isBlocked: false }, sessionData1.blueToken),
    /E_SESSION_NOT_FOUND/,
    'processBlueTurn must throw E_SESSION_NOT_FOUND'
  );

  await assert.rejects(
    broker.processBlueTurn(sess1Id, { isBlocked: false }, invalidToken),
    /Vault Deny:/,
    'processBlueTurn must reject on invalid token'
  );

  // 3i. Complete Blue turn legitimately -> advances to CONCLUDE
  const blueResult = await broker.processBlueTurn(sess1Id, { isBlocked: true, defenseVerdict: 'ADVERSARIAL_DETECTED' }, sessionData1.blueToken);
  assert.strictEqual(blueResult.phase, 'CONCLUDE');

  // 3j. Acting on CONCLUDE session: attempting Blue turn again
  await assert.rejects(
    broker.processBlueTurn(sess1Id, { isBlocked: false }, sessionData1.blueToken),
    /State Machine Error: Cannot process BLUE_TURN while in phase 'CONCLUDE'/,
    'processBlueTurn must reject acting on concluded session'
  );

  // 3k. getDisclosureBundle() branches:
  // Non-existent session
  await assert.rejects(
    broker.getDisclosureBundle('missing_session', sessionData1.blueToken),
    /E_SESSION_NOT_FOUND/
  );

  // Policy branch: REDACTED_DEFENSE (sess1)
  const bundleRedacted = await broker.getDisclosureBundle(sess1Id, sessionData1.blueToken);
  assert(bundleRedacted.disclosedAttackPayload.includes('[REDACTED_ATTACK_CATEGORY_JAILBREAK: length=13]'));

  // Policy branch: FULL_BENCHMARK
  const sessionFull = await broker.createSession('FULL_BENCHMARK');
  await broker.processRedTurn(sessionFull.sessionId, 'full_unredacted_payload_123', sessionFull.redToken);
  await broker.processBlueTurn(sessionFull.sessionId, { isBlocked: false }, sessionFull.blueToken);
  const bundleFull = await broker.getDisclosureBundle(sessionFull.sessionId, sessionFull.blueToken);
  assert.strictEqual(bundleFull.disclosedAttackPayload, 'full_unredacted_payload_123');

  // Policy branch: Default / other (SUMMARY_ONLY, lines 262-263)
  const sessionSummary = await broker.createSession('UNKNOWN_POLICY_NAME');
  await broker.processRedTurn(sessionSummary.sessionId, 'payload_summary_test', sessionSummary.redToken);
  await broker.processBlueTurn(sessionSummary.sessionId, { isBlocked: false }, sessionSummary.blueToken);
  const bundleSummary = await broker.getDisclosureBundle(sessionSummary.sessionId, sessionSummary.blueToken);
  assert.strictEqual(bundleSummary.disclosedAttackPayload, '[SUMMARY_ONLY]');

  // Policy denial branch on getDisclosureBundle (when in RED_TURN phase)
  const sessionEarly = await broker.createSession('REDACTED_DEFENSE');
  await assert.rejects(
    broker.getDisclosureBundle(sessionEarly.sessionId, sessionEarly.blueToken),
    /OPA Deny:/,
    'getDisclosureBundle must throw OPA Deny when called prematurely'
  );

  // 3l. queryRedPayload() branches:
  // Non-existent session
  assert.throws(() => {
    broker.queryRedPayload('missing_session_id', sessionData1.blueToken);
  }, /E_SESSION_NOT_FOUND/);

  // Prohibited phase (RED_TURN)
  const prematureQuery = broker.queryRedPayload(sessionEarly.sessionId, sessionEarly.blueToken);
  assert.strictEqual(prematureQuery.allowed, false);

  // Permitted phase (DISCLOSURE / when allowed, lines 311-315)
  const disclosureQuery = broker.queryRedPayload(sess1Id, sessionData1.blueToken);
  assert.strictEqual(disclosureQuery.allowed, true);
  assert.strictEqual(disclosureQuery.payload, 'exploit_probe');

  // 3m. requestPrivilegedAction() branches:
  // Prohibited / Confused deputy
  const unauthAction = broker.requestPrivilegedAction(sess1Id, 'admin_system_override', sessionData1.blueToken);
  assert.strictEqual(unauthAction.allowed, false);
  assert.strictEqual(unauthAction.code, 'E_CONFUSED_DEPUTY_BLOCKED');

  // Permitted privileged action with scoped capability token (lines 331-332)
  const adminToken = smVault.issueToken({
    tenantId: 'admin',
    sessionId: sess1Id,
    allowedActions: ['admin_system_override']
  });
  const authAction = broker.requestPrivilegedAction(sess1Id, 'admin_system_override', adminToken);
  assert.strictEqual(authAction.allowed, true);
  assert.strictEqual(authAction.action, 'admin_system_override');

  console.log('✓ BrokerStateMachine branch tests passed cleanly.');

  // =========================================================================
  // 4. EvaluationIntegrityEngine Branch Tests
  // =========================================================================
  const integrityEngine = new EvaluationIntegrityEngine();
  const goodEvidence = {
    canaryResult: { passed: true },
    modelHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    configHash: 'cfg_a1b2c3d4e5f6',
    datasetHash: 'data_advbench_v1_hash',
    infraErrors: [],
    retries: 0,
    resourceConsumption: { cpuPeak: 45, memoryPeak: 60 },
    auditReconstructable: true
  };

  const goodVerdict = integrityEngine.evaluateFinding(goodEvidence);
  assert.strictEqual(goodVerdict.verdict, 'CERTIFIED_SAFETY_FINDING');
  assert.strictEqual(goodVerdict.certified, true);

  const canaryFailVerdict = integrityEngine.evaluateFinding({ ...goodEvidence, canaryResult: { passed: false } });
  assert.strictEqual(canaryFailVerdict.verdict, 'HARNESS_ERROR_CONTAMINATED_MODEL');
  assert.strictEqual(canaryFailVerdict.certified, false);

  const hashDriftVerdict = integrityEngine.evaluateFinding({ ...goodEvidence, modelHash: 'deadbeef_wrong_hash' });
  assert.strictEqual(hashDriftVerdict.verdict, 'HARNESS_ERROR_CONFIG_DRIFT');

  const infraFailVerdict = integrityEngine.evaluateFinding({ ...goodEvidence, infraErrors: ['ETIMEDOUT'], retries: 1 });
  assert.strictEqual(infraFailVerdict.verdict, 'INFRA_FAILURE');

  const quotaVerdict = integrityEngine.evaluateFinding({ ...goodEvidence, resourceConsumption: { cpuPeak: 95, memoryPeak: 91 } });
  assert.strictEqual(quotaVerdict.verdict, 'ATTACKER_INDUCED_RESOURCE_ANOMALY');

  const unverifiedVerdict = integrityEngine.evaluateFinding({ ...goodEvidence, auditReconstructable: false });
  assert.strictEqual(unverifiedVerdict.verdict, 'UNVERIFIED');

  console.log('✓ EvaluationIntegrityEngine branch tests passed cleanly.');

  // =========================================================================
  // 5. WormAuditStore Branch Tests
  // =========================================================================
  const worm = new WormAuditStore();

  assert.throws(() => worm.query('red'), /E_AUDIT_WRITE_ONLY/);
  assert.throws(() => worm.query('blue'), /E_AUDIT_WRITE_ONLY/);

  worm.append({ sessionId: 'sess_q1', tenant: 'SYSTEM', eventType: 'TEST_EVENT', payload: 'data1' });
  const systemResults = worm.query('broker', { tenant: 'SYSTEM' });
  assert(Array.isArray(systemResults));
  assert(systemResults.every(e => e.tenant === 'SYSTEM'));

  const sessionResults = worm.query('broker', { sessionId: 'sess_q1', eventType: 'TEST_EVENT' });
  assert(Array.isArray(sessionResults));

  const storedRoot = worm.getMerkleRoot(true);
  assert(typeof storedRoot === 'string' && storedRoot.length === 64);

  assert.throws(() => worm.simulateTamper(-1, 'eventType', 'x'), /Invalid block index/);
  assert.throws(() => worm.simulateTamper(9999, 'eventType', 'x'), /Invalid block index/);

  // Tamper Merkle divergence detection
  const tamperWorm = new WormAuditStore();
  tamperWorm.append({ sessionId: 's1', tenant: 'SYSTEM', eventType: 'EV_A', payload: 'a' });
  tamperWorm.append({ sessionId: 's2', tenant: 'SYSTEM', eventType: 'EV_B', payload: 'b' });
  if (tamperWorm.anchors.length > 0) {
    const lastAnchor = tamperWorm.anchors[tamperWorm.anchors.length - 1];
    lastAnchor.merkleRoot = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    lastAnchor.blockCount = tamperWorm.chain.length;
    const tamperReport = tamperWorm.verifyIntegrity();
    assert.strictEqual(tamperReport.isValid, false);
  }

  console.log('✓ WormAuditStore branch tests passed cleanly.');

  // =========================================================================
  // 6. DedicatedInferenceWorker Lifecycle Guardrail Tests
  // =========================================================================
  const DedicatedInferenceWorker = require('../src/model/inference_worker');

  const rawWorker = new DedicatedInferenceWorker('test-lifecycle-guard');
  assert.throws(() => rawWorker.initialize(), /cannot INITIALIZE from status UNINITIALIZED/);

  const rawWorker2 = new DedicatedInferenceWorker('test-infer-guard');
  rawWorker2.create('sess-infer-guard');
  assert.throws(() => rawWorker2.infer('some prompt'), /Inference rejected/);

  const contaminatedWorker = new DedicatedInferenceWorker('test-canary-worker');
  contaminatedWorker.create('sess-canary');
  contaminatedWorker.initialize();
  contaminatedWorker.infer('test prompt', { simulateContamination: true });
  const canaryCheckFail = contaminatedWorker.verifyCanary();
  assert.strictEqual(canaryCheckFail.passed, false);
  assert.strictEqual(contaminatedWorker.status, 'CONTAMINATED_INSTANCE');

  const destroyedWorker = new DedicatedInferenceWorker('test-destroy-worker');
  destroyedWorker.create('sess-destroy');
  destroyedWorker.initialize();
  const destroyResult = destroyedWorker.destroy();
  assert.strictEqual(destroyResult.status, 'DESTROYED');
  assert.strictEqual(destroyResult.memoryScrubbed, true);
  assert.throws(() => destroyedWorker.infer('post-destroy'), /Inference rejected/);

  console.log('✓ DedicatedInferenceWorker lifecycle guardrail tests passed cleanly.');

  // =========================================================================
  // 7. OpaPolicyEngine Boundary Tests
  // =========================================================================
  const opaPdp = new OpaPolicyEngine();

  const noRuleResult = opaPdp.evaluateNetworkConnection('unknown_tenant', 'unknown_dest');
  assert.strictEqual(noRuleResult.verdict, 'DENY');
  assert.strictEqual(noRuleResult.code, 'E_DEFAULT_DENY');

  const modelEgress = opaPdp.evaluateNetworkConnection('model', 'internet');
  assert.strictEqual(modelEgress.verdict, 'DENY');
  assert.strictEqual(modelEgress.code, 'E_MODEL_EGRESS_BLOCKED');

  const redToModel = opaPdp.evaluateNetworkConnection('red', 'model');
  assert.strictEqual(redToModel.verdict, 'DENY');
  assert.strictEqual(redToModel.code, 'E_DIRECT_MODEL_DENIED');

  const blueToModel = opaPdp.evaluateNetworkConnection('blue', 'model');
  assert.strictEqual(blueToModel.verdict, 'DENY');
  assert.strictEqual(blueToModel.code, 'E_DIRECT_MODEL_DENIED');

  const prematureBundle = opaPdp.evaluateInformationFlow({ source: 'broker', destination: 'auditor', requestType: 'GET_DISCLOSURE_BUNDLE', sessionPhase: 'RED_TURN' });
  assert.strictEqual(prematureBundle.allowed, false);
  assert.strictEqual(prematureBundle.code, 'E_PREMATURE_DISCLOSURE');

  const validBundle = opaPdp.evaluateInformationFlow({ source: 'broker', destination: 'auditor', requestType: 'GET_DISCLOSURE_BUNDLE', sessionPhase: 'CONCLUDE', disclosurePolicy: 'REDACTED_DEFENSE' });
  assert.strictEqual(validBundle.allowed, true);

  const defaultAllow = opaPdp.evaluateInformationFlow({ source: 'broker', destination: 'auditor', requestType: 'SOME_ALLOWED_REQUEST', sessionPhase: 'VERIFY' });
  assert.strictEqual(defaultAllow.allowed, true);

  const defenseProtected = opaPdp.evaluateInformationFlow({ source: 'red', destination: 'red', requestType: 'READ_BLUE_DEFENSE_LOGIC', sessionPhase: 'RED_TURN' });
  assert.strictEqual(defenseProtected.allowed, false);
  assert.strictEqual(defenseProtected.code, 'E_DEFENSE_LOGIC_PROTECTED');

  console.log('✓ OpaPolicyEngine boundary tests passed cleanly.');

  // =========================================================================
  // 8. VaultAuthority refreshToken branch Tests
  // =========================================================================
  const vaultNoRefresh = new VaultAuthority('TEST_KEY_NO_REFRESH');
  const tokenForRefresh = vaultNoRefresh.issueToken({ tenantId: 'red', sessionId: 'sess_refresh', allowedActions: ['submit_attack'] });
  const noRefreshResult = vaultNoRefresh.refreshToken(tokenForRefresh);
  assert.strictEqual(noRefreshResult.success, false);
  assert(/E_REFRESH_DISABLED/.test(noRefreshResult.reason));

  console.log('✓ VaultAuthority refreshToken branch tests passed cleanly.');

  // =========================================================================
  // 9. SideChannelMitigations: additional branches
  // =========================================================================
  const normalQuantized = sideChannelMitigations.quantizeResponseTime(100);
  assert(normalQuantized >= 100);

  const redNode = sideChannelMitigations.getIsolatedNodeAssignment('red');
  assert(typeof redNode.node === 'string');
  const blueNode = sideChannelMitigations.getIsolatedNodeAssignment('blue');
  assert(typeof blueNode.node === 'string');
  const modelNode = sideChannelMitigations.getIsolatedNodeAssignment('model');
  assert(typeof modelNode.node === 'string');

  console.log('✓ SideChannelMitigations additional branch tests passed cleanly.');

  // =========================================================================
  // 10. Tenant Sandbox Guardrail Tests (via OPA-stubbed instances)
  // =========================================================================
  const { RedSandbox, BlueSandbox } = require('../src/sandboxes/tenant_sandboxes');

  const stubOpaAllow = { evaluateNetworkConnection: () => ({ verdict: 'ALLOW' }) };
  const stubOpaDeny = { evaluateNetworkConnection: () => ({ verdict: 'DENY', reason: 'Mock CNI deny' }) };
  const stubAudit = { append: () => {} };
  const stubVault = {};
  const stubBroker = {
    processRedTurn: async (sid, text) => ({ sessionId: sid, payloadText: text }),
    processBlueTurn: async (sid, result) => ({ sessionId: sid, result }),
    queryRedPayload: () => ({ allowed: false })
  };

  const redSandbox = new RedSandbox(stubBroker, stubAudit, stubOpaAllow, stubVault);
  const blueSandbox = new BlueSandbox(stubBroker, stubAudit, stubOpaAllow, stubVault);

  // 10a. Red submitAttack with empty payload → Schema Error
  await assert.rejects(
    redSandbox.submitAttack('sess-guard', '', {}),
    /Schema Error/,
    'Empty payload must throw Schema Error'
  );

  // 10b. Red submitAttack with whitespace-only payload → Schema Error
  await assert.rejects(
    redSandbox.submitAttack('sess-guard', '   ', {}),
    /Schema Error/,
    'Whitespace payload must throw Schema Error'
  );

  // 10c. Red attemptHostInspection with dropped PTRACE → DENY
  const redDenySandbox = new RedSandbox(stubBroker, stubAudit, stubOpaDeny, stubVault);
  const hostInspect = redDenySandbox.attemptHostInspection();
  assert.strictEqual(hostInspect.verdict, 'DENY');
  assert.strictEqual(hostInspect.code, 'E_KATA_VM_ISOLATED');

  // 10d. Red attemptHostInspection without PTRACE in dropped caps (allow path)
  const redPermissiveSandbox = new RedSandbox(stubBroker, stubAudit, stubOpaAllow, stubVault);
  redPermissiveSandbox.kataVmConfig.droppedCapabilities = ['CAP_NET_RAW', 'CAP_SYS_ADMIN'];
  const hostAllowed = redPermissiveSandbox.attemptHostInspection();
  assert.strictEqual(hostAllowed.verdict, 'ALLOW');

  // 10e. Blue evaluateDefense with CNI deny path
  const blueDenySandbox = new BlueSandbox(stubBroker, stubAudit, stubOpaDeny, stubVault);
  await assert.rejects(
    blueDenySandbox.evaluateDefense('sess-deny', 'some model output', {}),
    /CNI Deny/,
    'evaluateDefense must throw CNI Deny when OPA denies'
  );

  // 10f. Blue attemptDirectConnectToRed → DENY (use real OPA)
  const realOpaForTest = new OpaPolicyEngine();
  const blueSandboxRealOpa = new BlueSandbox(stubBroker, stubAudit, realOpaForTest, stubVault);
  const directConnect = blueSandboxRealOpa.attemptDirectConnectToRed();
  assert.strictEqual(directConnect.verdict, 'DENY');

  console.log('✓ Tenant sandbox guardrail branch tests passed cleanly.');

  console.log('\nAll subsystems unit tests passed cleanly!');
}

runSubsystemsUnitTests().catch(err => {
  console.error('Subsystems unit tests failed:', err);
  process.exit(1);
});
