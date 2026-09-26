/**
 * Bayora Broker & Session State Machine
 * Section B, E, Q: Mandatory-Mediation Broker
 * State Machine: SETUP -> RED_TURN -> MODEL_INFERENCE -> EVAL -> BLUE_TURN -> CONCLUDE -> DISCLOSURE
 * Fail-Closed, Minimal, Auditable Orchestrator.
 */

const crypto = require('crypto');
const DedicatedInferenceWorker = require('../model/inference_worker');
const EvaluationIntegrityEngine = require('../eval/integrity');
const sideChannelMitigations = require('../sidechannel/mitigations');

class BrokerStateMachine {
  constructor(auditStore, opaPdp, vaultAuthority) {
    this.audit = auditStore;
    this.opa = opaPdp;
    this.vault = vaultAuthority;
    this.integrityEngine = new EvaluationIntegrityEngine();

    // Map of active sessions: sessionId -> SessionState
    this.sessions = new Map();
  }

  /**
   * STEP 1: SETUP
   * Initializes a fresh session with non-monotonic UUIDs and dedicated worker.
   */
  async createSession(disclosurePolicy = 'REDACTED_DEFENSE') {
    // Generate UUIDv4 to avoid monotonic counter leakage (§X)
    const sessionId = `sess_${crypto.randomUUID()}`;
    const startTime = Date.now();

    // Instantiate fresh, non-shared inference worker
    const worker = new DedicatedInferenceWorker();
    worker.create(sessionId);
    worker.initialize();

    // Issue short-lived, session-scoped capability tokens for Red and Blue (§J)
    const redToken = this.vault.issueToken({
      tenantId: 'red',
      sessionId,
      allowedActions: ['submit_attack', 'read_coarse_status']
    });

    const blueToken = this.vault.issueToken({
      tenantId: 'blue',
      sessionId,
      allowedActions: ['submit_defense', 'read_coarse_status', 'read_disclosure']
    });

    const session = {
      sessionId,
      phase: 'SETUP',
      disclosurePolicy,
      worker,
      redPayload: null,
      modelResponse: null,
      blueEvaluation: null,
      integrityVerdict: null,
      infraErrors: [],
      retries: 0,
      resourceConsumption: { cpuPeak: 42, memoryPeak: 55 },
      tokens: { redToken, blueToken },
      createdAt: new Date().toISOString()
    };

    this.sessions.set(sessionId, session);

    // Log to WORM audit store
    this.audit.append({
      sessionId,
      tenant: 'SYSTEM',
      actor: 'broker-orchestrator',
      eventType: 'SESSION_INITIALIZED',
      payload: { sessionId, phase: 'SETUP' },
      details: { disclosurePolicy, isolationTier: 'Kata-microVM', dedicatedWorker: worker.workerId }
    });

    // Advance to RED_TURN
    session.phase = 'RED_TURN';
    return {
      sessionId,
      phase: session.phase,
      redToken,
      blueToken,
      dedicatedWorkerId: worker.workerId
    };
  }

  /**
   * STEP 2: RED_TURN
   * Accepts attack payload from Red sandbox verified via capability token.
   */
  async processRedTurn(sessionId, payloadText, token) {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error('E_SESSION_NOT_FOUND');

    if (session.phase !== 'RED_TURN') {
      throw new Error(`State Machine Error: Cannot process RED_TURN while in phase '${session.phase}'`);
    }

    // Capability check via Vault (§J)
    const capCheck = this.vault.validateCapability(token, 'submit_attack', sessionId);
    if (!capCheck.valid) {
      throw new Error(`Vault Deny: ${capCheck.reason}`);
    }

    session.redPayload = payloadText;
    session.phase = 'MODEL_INFERENCE';

    this.audit.append({
      sessionId,
      tenant: 'red',
      actor: 'red-sandbox',
      eventType: 'STATE_TRANSITION',
      payload: { from: 'RED_TURN', to: 'MODEL_INFERENCE' },
      details: { payloadDigest: crypto.createHash('sha256').update(payloadText).digest('hex') }
    });

    // Automatically trigger model inference
    return await this._executeModelInference(sessionId);
  }

  /**
   * STEP 3 & 4: MODEL_INFERENCE & EVAL
   * Dispatches payload to dedicated model worker, runs canary check, evaluates integrity.
   */
  async _executeModelInference(sessionId, options = {}) {
    const session = this.sessions.get(sessionId);
    const startTs = Date.now();

    try {
      // 1. Run inference on isolated worker
      const inferResult = session.worker.infer(session.redPayload, options);
      session.modelResponse = inferResult;

      // 2. Automated Canary Probe Verification (§K)
      const canaryCheck = session.worker.verifyCanary();

      // 3. Evaluation Integrity check (§L)
      const integrityVerdict = this.integrityEngine.evaluateFinding({
        canaryResult: canaryCheck,
        modelHash: session.worker.pinnedWeightsHash,
        configHash: 'cfg_a1b2c3d4e5f6',
        datasetHash: 'data_advbench_v1_hash',
        infraErrors: session.infraErrors,
        retries: session.retries,
        resourceConsumption: session.resourceConsumption,
        auditReconstructable: true,
        rawFinding: inferResult
      });

      session.integrityVerdict = integrityVerdict;
      session.phase = 'BLUE_TURN';

      const rawElapsed = Date.now() - startTs;
      const quantizedElapsed = sideChannelMitigations.quantizeResponseTime(rawElapsed);

      this.audit.append({
        sessionId,
        tenant: 'model',
        actor: session.worker.workerId,
        eventType: 'MODEL_INFERENCE_COMPLETED',
        payload: { isJailbreak: inferResult.isJailbreak, certifiedVerdict: integrityVerdict.verdict },
        details: { rawElapsedMs: rawElapsed, quantizedElapsedMs: quantizedElapsed, canaryPassed: canaryCheck.passed }
      });

      return {
        sessionId,
        phase: session.phase,
        isJailbreak: inferResult.isJailbreak,
        integrityVerdict,
        quantizedLatencyMs: quantizedElapsed
      };
    } catch (err) {
      session.infraErrors.push(err.message);
      session.phase = 'INFRA_FAILURE';
      this.audit.append({
        sessionId,
        tenant: 'SYSTEM',
        actor: 'broker-orchestrator',
        eventType: 'INFRASTRUCTURE_FAILURE',
        payload: { error: err.message },
        details: { phase: 'MODEL_INFERENCE' }
      });
      throw err;
    }
  }

  /**
   * STEP 5: BLUE_TURN
   * Blue sandbox evaluates defense on filtered model response.
   */
  async processBlueTurn(sessionId, blueVerdict, token) {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error('E_SESSION_NOT_FOUND');

    if (session.phase !== 'BLUE_TURN') {
      throw new Error(`State Machine Error: Cannot process BLUE_TURN while in phase '${session.phase}'`);
    }

    const capCheck = this.vault.validateCapability(token, 'submit_defense', sessionId);
    if (!capCheck.valid) {
      throw new Error(`Vault Deny: ${capCheck.reason}`);
    }

    session.blueEvaluation = blueVerdict;
    session.phase = 'CONCLUDE';

    // Step 5 of lifecycle: DESTROY the inference worker instance (§K)
    session.worker.destroy();

    this.audit.append({
      sessionId,
      tenant: 'blue',
      actor: 'blue-sandbox',
      eventType: 'STATE_TRANSITION',
      payload: { from: 'BLUE_TURN', to: 'CONCLUDE' },
      details: { blueVerdict: blueVerdict.defenseVerdict }
    });

    return {
      sessionId,
      phase: session.phase,
      status: 'TEST_CONCLUDED',
      readyForDisclosure: true
    };
  }

  /**
   * STEP 6 & 7: CONCLUDE & DISCLOSURE
   * Retrieve post-conclusion disclosure bundle based on OPA disclosure policy.
   */
  async getDisclosureBundle(sessionId, token) {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error('E_SESSION_NOT_FOUND');

    // Check OPA information flow policy
    const policyCheck = this.opa.evaluateInformationFlow({
      source: 'broker',
      destination: 'blue',
      requestType: 'GET_DISCLOSURE_BUNDLE',
      sessionPhase: session.phase,
      disclosurePolicy: session.disclosurePolicy
    });

    if (!policyCheck.allowed) {
      throw new Error(`OPA Deny: ${policyCheck.reason}`);
    }

    // Advance to final state DISCLOSURE
    session.phase = 'DISCLOSURE';

    // Apply redaction based on policy (§F)
    let payloadForBlue = null;
    if (session.disclosurePolicy === 'FULL_BENCHMARK') {
      payloadForBlue = session.redPayload;
    } else if (session.disclosurePolicy === 'REDACTED_DEFENSE') {
      // Redact specific sensitive exploit mechanics
      payloadForBlue = session.redPayload ? `[REDACTED_ATTACK_CATEGORY_JAILBREAK: length=${session.redPayload.length}]` : null;
    } else {
      payloadForBlue = '[SUMMARY_ONLY]';
    }

    const bundle = {
      sessionId,
      phase: session.phase,
      disclosurePolicy: session.disclosurePolicy,
      modelSafetyFinding: session.modelResponse ? session.modelResponse.isJailbreak : false,
      blueEvaluation: session.blueEvaluation,
      certifiedIntegrity: session.integrityVerdict,
      disclosedAttackPayload: payloadForBlue,
      concludedAt: new Date().toISOString()
    };

    this.audit.append({
      sessionId,
      tenant: 'SYSTEM',
      actor: 'broker-orchestrator',
      eventType: 'DISCLOSURE_BUNDLE_RELEASED',
      payload: { sessionId, policy: session.disclosurePolicy },
      details: { disclosedTo: 'blue', integrityCertified: session.integrityVerdict.certified }
    });

    return bundle;
  }

  /**
   * Information Flow Enforcement Check:
   * Blue attempts to query Red payload during an unauthorized phase.
   */
  queryRedPayload(sessionId, token) {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error('E_SESSION_NOT_FOUND');

    const flowEval = this.opa.evaluateInformationFlow({
      source: 'red',
      destination: 'blue',
      requestType: 'READ_RED_PAYLOAD',
      sessionPhase: session.phase
    });

    if (!flowEval.allowed) {
      return {
        allowed: false,
        code: flowEval.code,
        reason: flowEval.reason,
        currentPhase: session.phase
      };
    }

    return {
      allowed: true,
      payload: session.redPayload
    };
  }

  /**
   * Confused Deputy Check (§J):
   * Rejects requests where caller attempts to invoke elevated action without requisite token.
   */
  requestPrivilegedAction(sessionId, action, token) {
    const capCheck = this.vault.validateCapability(token, action, sessionId);
    if (!capCheck.valid) {
      return {
        allowed: false,
        code: 'E_CONFUSED_DEPUTY_BLOCKED',
        reason: `Broker rejection: Confused Deputy blocked. Tenant cannot invoke action '${action}' without scoped capability credential.`
      };
    }

    return { allowed: true, action };
  }

  getSession(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) return null;
    return {
      sessionId: session.sessionId,
      phase: session.phase,
      disclosurePolicy: session.disclosurePolicy,
      integrityVerdict: session.integrityVerdict,
      createdAt: session.createdAt,
      workerStatus: session.worker ? session.worker.status : 'N/A'
    };
  }
}

module.exports = BrokerStateMachine;
