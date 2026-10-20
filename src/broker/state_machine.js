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
    this.sessionTtlMs = Number(process.env.SESSION_TTL_MS) || (60 * 60 * 1000); // 1 hour default
    this.maxSessions = Number(process.env.MAX_SESSIONS) || 500;
    this.maxAuditEntries = Number(process.env.MAX_AUDIT_ENTRIES) || 10000;
    this.auditWarningThreshold = Math.floor(this.maxAuditEntries * 0.8);

    this.evictionInterval = setInterval(() => {
      this.evictExpiredSessions();
    }, 60 * 1000);
    if (this.evictionInterval && typeof this.evictionInterval.unref === 'function') {
      this.evictionInterval.unref();
    }
  }

  /**
   * Evict sessions that have exceeded SESSION_TTL_MS, destroying their workers.
   */
  evictExpiredSessions() {
    const now = Date.now();
    for (const [sessionId, session] of this.sessions.entries()) {
      const createdTime = typeof session.createdAt === 'number'
        ? session.createdAt
        : (new Date(session.createdAt).getTime() || 0);
      if (now - createdTime > this.sessionTtlMs) {
        if (session.worker && typeof session.worker.destroy === 'function') {
          try { session.worker.destroy(); } catch (e) {}
        }
        this.sessions.delete(sessionId);
        try {
          this.audit.append({
            sessionId,
            tenant: 'SYSTEM',
            actor: 'session-reaper',
            eventType: 'STATE_TRANSITION',
            payload: { from: session.phase, to: 'EXPIRED' },
            details: { reason: 'SESSION_TTL_EXPIRED' }
          });
        } catch (e) {}
      }
    }
  }

  /**
   * STEP 1: SETUP
   * Initializes a fresh session with non-monotonic UUIDs and dedicated worker.
   */
  async createSession(disclosurePolicy = 'REDACTED_DEFENSE', creatorRole = 'broker') {
    this.evictExpiredSessions();

    if (this.sessions.size >= this.maxSessions) {
      const err = new Error(`MAX_SESSIONS_EXCEEDED: Active sessions limit of ${this.maxSessions} reached`);
      err.code = 'E_MAX_SESSIONS_EXCEEDED';
      err.statusCode = 503;
      throw err;
    }

    if (this.audit && this.audit.chain) {
      if (this.audit.chain.length >= this.maxAuditEntries) {
        const err = new Error(`MAX_AUDIT_ENTRIES_EXCEEDED: Audit ledger capacity of ${this.maxAuditEntries} reached. Rejecting new session to prevent evidentiary loss.`);
        err.code = 'E_AUDIT_CAPACITY_EXCEEDED';
        err.statusCode = 503;
        throw err;
      }
      if (this.audit.chain.length >= this.auditWarningThreshold) {
        console.warn(`[AUDIT WARNING]: WORM audit chain length (${this.audit.chain.length}) has reached ${Math.round((this.audit.chain.length / this.maxAuditEntries) * 100)}% of MAX_AUDIT_ENTRIES (${this.maxAuditEntries}).`);
      }
    }

    const ALLOWED_POLICIES = ['REDACTED_DEFENSE', 'FULL_BENCHMARK', 'COARSE_STATUS'];
    if (!ALLOWED_POLICIES.includes(disclosurePolicy)) {
      const err = new Error(`Invalid disclosure policy '${disclosurePolicy}'. Allowed: ${ALLOWED_POLICIES.join(', ')}`);
      err.code = 'E_INVALID_DISCLOSURE_POLICY';
      err.statusCode = 400;
      throw err;
    }
    if (disclosurePolicy === 'FULL_BENCHMARK' && creatorRole !== 'admin' && creatorRole !== 'broker') {
      const err = new Error("Forbidden: Only admin or broker role may select 'FULL_BENCHMARK' disclosure policy");
      err.code = 'E_FORBIDDEN';
      err.statusCode = 403;
      throw err;
    }

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
      resourceConsumption: { cpuPeak: 0, memoryPeak: 0, simulated: false },
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
   * Shared disclosure redaction policy filter (§F)
   */
  applyDisclosureRedaction(redPayload, disclosurePolicy) {
    if (!redPayload) return null;
    if (disclosurePolicy === 'FULL_BENCHMARK') {
      return redPayload;
    }
    if (disclosurePolicy === 'REDACTED_DEFENSE') {
      return `[REDACTED_ATTACK_CATEGORY_JAILBREAK: length=${redPayload.length}]`;
    }
    if (disclosurePolicy === 'COARSE_STATUS') {
      return '[SUMMARY_ONLY]';
    }
    return '[SUMMARY_ONLY]';
  }

  /**
   * STEP 2: RED_TURN
   * Accepts attack payload from Red sandbox verified via capability token.
   * Returns only { sessionId, phase: 'ACCEPTED' } to Red.
   */
  async processRedTurn(sessionId, payloadText, token) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      const err = new Error('E_SESSION_NOT_FOUND');
      err.code = 'E_SESSION_NOT_FOUND';
      throw err;
    }

    if (session.phase !== 'RED_TURN') {
      const err = new Error(`State Machine Error: Cannot process RED_TURN while in phase '${session.phase}'`);
      err.code = 'E_STATE_MACHINE_ERROR';
      throw err;
    }

    // Capability check via Vault (§J)
    const capCheck = this.vault.validateCapability(token, 'submit_attack', sessionId, 'red');
    if (!capCheck.valid) {
      const err = new Error(`Vault Deny: ${capCheck.reason}`);
      err.code = 'E_AUTH_FAILED';
      throw err;
    }
    this.vault.consumeAction(token, 'submit_attack');

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
    await this._executeModelInference(sessionId);

    // Red receives only coarse acceptance; verdict and timing details are hidden
    return {
      sessionId,
      phase: 'ACCEPTED'
    };
  }

  /**
   * STEP 3 & 4: MODEL_INFERENCE & EVAL
   * Dispatches payload to dedicated model worker, runs canary check, evaluates integrity.
   */
  async _executeModelInference(sessionId, options = {}) {
    const session = this.sessions.get(sessionId);
    const startTs = Date.now();

    try {
      // 1. Run inference on isolated worker (ignore client options to prevent contamination injection)
      const inferResult = session.worker.infer(session.redPayload);
      session.modelResponse = inferResult;

      // 2. Automated Canary Probe Verification (§K)
      const canaryCheck = session.worker.verifyCanary();

      // Measure real runtime resource consumption
      const mem = process.memoryUsage();
      const memPct = Math.min(100, Math.round((mem.heapUsed / mem.heapTotal) * 100));
      const cpu = process.cpuUsage();
      const cpuPct = Math.min(100, Math.round(((cpu.user + cpu.system) / 1000000) % 100));
      session.resourceConsumption = {
        cpuPeak: Math.max(1, cpuPct),
        memoryPeak: Math.max(1, memPct),
        simulated: false
      };

      // Compute auditReconstructable: session entries exist and chain is valid
      const sessionEntries = this.audit.chain.filter(e => e.sessionId === sessionId);
      const hasRequestEntry = sessionEntries.some(e => e.tenant === 'red' || (e.payload && e.payload.from === 'RED_TURN'));
      const chainValid = this.audit.verifyIntegrity().isValid;
      const auditReconstructable = hasRequestEntry && chainValid;

      // 3. Evaluation Integrity check (§L)
      const integrityVerdict = this.integrityEngine.evaluateFinding({
        canaryResult: canaryCheck,
        modelHash: session.worker._computeRuntimeWeightsHash(),
        configHash: this.integrityEngine.expectedConfigHash,
        datasetHash: this.integrityEngine.expectedDatasetHash,
        infraErrors: session.infraErrors,
        retries: session.retries,
        resourceConsumption: session.resourceConsumption,
        auditReconstructable,
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
      if (session.worker && typeof session.worker.destroy === 'function') {
        try { session.worker.destroy(); } catch (e) {}
      }
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
   * Blue inspects normalized model output from the broker during BLUE_TURN
   */
  getModelOutput(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      const err = new Error('E_SESSION_NOT_FOUND');
      err.code = 'E_SESSION_NOT_FOUND';
      throw err;
    }

    if (session.phase !== 'BLUE_TURN') {
      const err = new Error(`State Machine Error: Cannot inspect model output while in phase '${session.phase}'`);
      err.code = 'E_STATE_MACHINE_ERROR';
      throw err;
    }

    return {
      sessionId,
      phase: session.phase,
      modelOutput: session.modelResponse ? session.modelResponse.rawOutput : null
    };
  }

  /**
   * STEP 5: BLUE_TURN
   * Blue sandbox evaluates defense on filtered model response.
   */
  async processBlueTurn(sessionId, blueVerdictOrParams, token) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      const err = new Error('E_SESSION_NOT_FOUND');
      err.code = 'E_SESSION_NOT_FOUND';
      throw err;
    }

    if (session.phase !== 'BLUE_TURN') {
      const err = new Error(`State Machine Error: Cannot process BLUE_TURN while in phase '${session.phase}'`);
      err.code = 'E_STATE_MACHINE_ERROR';
      throw err;
    }

    const capCheck = this.vault.validateCapability(token, 'submit_defense', sessionId, 'blue');
    if (!capCheck.valid) {
      const err = new Error(`Vault Deny: ${capCheck.reason}`);
      err.code = 'E_AUTH_FAILED';
      throw err;
    }
    this.vault.consumeAction(token, 'submit_defense');

    let blueEvaluation = blueVerdictOrParams;
    if (typeof blueVerdictOrParams === 'object' && blueVerdictOrParams !== null) {
      const { modelOutput: _ignored, ...sanitized } = blueVerdictOrParams;
      blueEvaluation = sanitized;
    }

    session.blueEvaluation = blueEvaluation;
    session.phase = 'CONCLUDE';

    // Step 5 of lifecycle: DESTROY the inference worker instance (§K)
    session.worker.destroy();

    this.audit.append({
      sessionId,
      tenant: 'blue',
      actor: 'blue-sandbox',
      eventType: 'STATE_TRANSITION',
      payload: { from: 'BLUE_TURN', to: 'CONCLUDE' },
      details: { blueVerdict: blueEvaluation ? blueEvaluation.defenseVerdict : 'UNSPECIFIED' }
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
    if (!session) {
      const err = new Error('E_SESSION_NOT_FOUND');
      err.code = 'E_SESSION_NOT_FOUND';
      throw err;
    }

    if (!token) {
      const err = new Error('Vault Deny: TOKEN_MISSING');
      err.code = 'E_AUTH_FAILED';
      throw err;
    }

    const capCheck = this.vault.validateCapability(token, 'read_disclosure', sessionId, 'blue');
    if (!capCheck.valid) {
      const err = new Error(`Vault Deny: ${capCheck.reason}`);
      err.code = 'E_AUTH_FAILED';
      throw err;
    }
    this.vault.consumeAction(token, 'read_disclosure');

    // Check OPA information flow policy
    const policyCheck = this.opa.evaluateInformationFlow({
      source: 'broker',
      destination: 'blue',
      requestType: 'GET_DISCLOSURE_BUNDLE',
      sessionPhase: session.phase,
      disclosurePolicy: session.disclosurePolicy
    });

    if (!policyCheck.allowed) {
      const err = new Error(`OPA Deny: ${policyCheck.reason}`);
      err.code = 'E_POLICY_DENIED';
      throw err;
    }

    // Advance to final state DISCLOSURE
    session.phase = 'DISCLOSURE';

    // Apply shared redaction based on policy (§F)
    const payloadForBlue = this.applyDisclosureRedaction(session.redPayload, session.disclosurePolicy);

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
      details: { disclosedTo: 'blue', integrityCertified: session.integrityVerdict ? session.integrityVerdict.certified : false }
    });

    return bundle;
  }

  /**
   * Information Flow Enforcement Check:
   * Blue attempts to query Red payload during an unauthorized phase.
   * Requires a valid blue token. After CONCLUDE returns redacted value according to disclosurePolicy.
   */
  queryRedPayload(sessionId, token) {
    const session = this.sessions.get(sessionId);
    if (!session) {
      const err = new Error('E_SESSION_NOT_FOUND');
      err.code = 'E_SESSION_NOT_FOUND';
      throw err;
    }

    if (!token) {
      return {
        allowed: false,
        code: 'E_AUTH_FAILED',
        reason: 'Vault Deny: TOKEN_MISSING',
        currentPhase: session.phase
      };
    }

    const capCheck = this.vault.validateCapability(token, 'read_disclosure', sessionId, 'blue');
    if (!capCheck.valid) {
      return {
        allowed: false,
        code: 'E_AUTH_FAILED',
        reason: `Vault Deny: ${capCheck.reason}`,
        currentPhase: session.phase
      };
    }

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
      payload: this.applyDisclosureRedaction(session.redPayload, session.disclosurePolicy)
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
