/**
 * Bayora Sandboxed Workloads: Red Sandbox & Blue Sandbox
 * Section H: Kata Containers VM Isolation (Target) & Worker Threads Isolation (Enforced)
 * Section I: Default-Deny Network Egress
 */

const { runInIsolatedWorker, DEFAULT_RESOURCE_LIMITS } = require('./worker_isolation');

class RedSandbox {
  constructor(brokerRef, auditRef, opaRef, vaultRef) {
    this.tenantId = 'red';
    this.broker = brokerRef;
    this.audit = auditRef;
    this.opa = opaRef;
    this.vault = vaultRef;
    this.workerResourceLimits = { ...DEFAULT_RESOURCE_LIMITS };
    this.kataVmConfig = {
      runtime: 'io.containerd.kata.v2',
      hypervisor: 'cloud-hypervisor',
      readOnlyRootfs: true,
      droppedCapabilities: ['CAP_NET_RAW', 'CAP_SYS_ADMIN', 'CAP_SYS_PTRACE'],
      sharedVolumes: [],
      cgroup: 'cpuset:0-3'
    };
  }

  /**
   * Submit an attack payload through the mediated Broker channel
   */
  async submitAttack(sessionId, payloadText, token, destination = 'broker', destinationIp = null) {
    // 1. Enforce network egress policy against destination
    const netCheck = this.opa.evaluateNetworkConnection('red', destination, destinationIp);
    if (netCheck.verdict !== 'ALLOW') {
      const err = new Error(`CNI Deny: ${netCheck.reason}`);
      err.code = 'E_OPA_NETWORK_DENY';
      throw err;
    }

    // 2. Validate session existence first
    if (this.broker && this.broker.sessions && typeof this.broker.sessions.get === 'function') {
      const session = this.broker.sessions.get(sessionId);
      if (!session) {
        const err = new Error('E_SESSION_NOT_FOUND');
        err.code = 'E_SESSION_NOT_FOUND';
        throw err;
      }
    }

    // 3. Validate capability token BEFORE phase check or expensive compute
    if (this.vault && typeof this.vault.validateCapability === 'function') {
      const capCheck = this.vault.validateCapability(token, 'submit_attack', sessionId, 'red');
      if (!capCheck.valid) {
        const err = new Error(`Vault Deny: ${capCheck.reason}`);
        err.code = 'E_AUTH_FAILED';
        throw err;
      }
    }

    // 4. Validate phase
    if (this.broker && this.broker.sessions && typeof this.broker.sessions.get === 'function') {
      const session = this.broker.sessions.get(sessionId);
      if (session && session.phase !== 'RED_TURN') {
        const err = new Error(`State Machine Error: Cannot process RED_TURN while in phase '${session.phase}'`);
        err.code = 'E_STATE_MACHINE_ERROR';
        throw err;
      }
    }

    // 5. Validate schema
    if (!payloadText || typeof payloadText !== 'string' || payloadText.trim().length === 0) {
      throw new Error('Schema Error: Red payload must be a non-empty string');
    }

    // 5. Submit to broker: atomic capability consumption and state transition
    const turnResult = await this.broker.processRedTurn(sessionId, payloadText, token);

    // 6. Compute digest and append to WORM audit store only after broker accepts the turn
    const workerResult = await runInIsolatedWorker(
      'red',
      { type: 'DIGEST', payloadText },
      this.workerResourceLimits
    );
    const digest = workerResult.digest;

    this.audit.append({
      sessionId,
      tenant: 'red',
      actor: 'red-sandbox-runner',
      eventType: 'ATTACK_PAYLOAD_SUBMITTED',
      payload: { digest },
      details: { sizeBytes: Buffer.byteLength(payloadText, 'utf8') }
    }, 'red');

    return turnResult;
  }

  /**
   * Probe foreign worker memory to prove isolate separation
   */
  probeForeignWorkerMemory() {
    return runInIsolatedWorker('red', { type: 'PROBE_FOREIGN_SECRET' }, this.workerResourceLimits);
  }

  /**
   * Exploit Attempt (Attack Sim): Try to connect directly to Blue Sandbox
   */
  attemptDirectConnectToBlue() {
    return this.opa.evaluateNetworkConnection('red', 'blue');
  }

  /**
   * Exploit Attempt (Attack Sim): Try to access Cloud Metadata Endpoint (IMDS)
   */
  attemptImdsAccess() {
    return this.opa.evaluateNetworkConnection('red', 'imds', '169.254.169.254');
  }

  /**
   * Exploit Attempt (Attack Sim): Try to inspect host /proc or mount
   */
  attemptHostInspection() {
    if (this.kataVmConfig.droppedCapabilities.includes('CAP_SYS_PTRACE')) {
      return {
        verdict: 'DENY',
        code: 'E_KATA_VM_ISOLATED',
        reason: 'Kata VM boundary prevents ptrace or host /proc enumeration across microVMs.'
      };
    }
    return { verdict: 'ALLOW' };
  }
}

class BlueSandbox {
  constructor(brokerRef, auditRef, opaRef, vaultRef) {
    this.tenantId = 'blue';
    this.broker = brokerRef;
    this.audit = auditRef;
    this.opa = opaRef;
    this.vault = vaultRef;
    this.workerResourceLimits = { ...DEFAULT_RESOURCE_LIMITS };
    this.defenseLogic = {
      classifierThreshold: 0.75,
      signatureKeywords: ['bypass', 'jailbreak', 'exploit', 'malware']
    };
    this.kataVmConfig = {
      runtime: 'io.containerd.kata.v2',
      hypervisor: 'cloud-hypervisor',
      readOnlyRootfs: true,
      droppedCapabilities: ['CAP_NET_RAW', 'CAP_SYS_ADMIN', 'CAP_SYS_PTRACE'],
      sharedVolumes: [],
      cgroup: 'cpuset:4-7'
    };
  }

  /**
   * Evaluate model output from defensive standpoint
   */
  async evaluateDefense(sessionId, modelOutput, token, destination = 'broker', destinationIp = null) {
    // 1. Enforce network egress policy against destination
    const netCheck = this.opa.evaluateNetworkConnection('blue', destination, destinationIp);
    if (netCheck.verdict !== 'ALLOW') {
      const err = new Error(`CNI Deny: ${netCheck.reason}`);
      err.code = 'E_OPA_NETWORK_DENY';
      throw err;
    }

    // 2. Validate session existence first
    if (this.broker && this.broker.sessions && typeof this.broker.sessions.get === 'function') {
      const session = this.broker.sessions.get(sessionId);
      if (!session) {
        const err = new Error('E_SESSION_NOT_FOUND');
        err.code = 'E_SESSION_NOT_FOUND';
        throw err;
      }
    }

    // 3. Validate capability token BEFORE phase check or expensive compute
    if (this.vault && typeof this.vault.validateCapability === 'function') {
      const capCheck = this.vault.validateCapability(token, 'submit_defense', sessionId, 'blue');
      if (!capCheck.valid) {
        const err = new Error(`Vault Deny: ${capCheck.reason}`);
        err.code = 'E_AUTH_FAILED';
        throw err;
      }
    }

    // 4. Validate phase
    if (this.broker && this.broker.sessions && typeof this.broker.sessions.get === 'function') {
      const session = this.broker.sessions.get(sessionId);
      if (session && session.phase !== 'BLUE_TURN') {
        const err = new Error(`State Machine Error: Cannot process BLUE_TURN while in phase '${session.phase}'`);
        err.code = 'E_STATE_MACHINE_ERROR';
        throw err;
      }
    }

    // Blue receives normalized model output from the broker, never trusting client-supplied text
    let textToScan = '';
    if (this.broker && typeof this.broker.getModelOutput === 'function') {
      try {
        const brokerOutput = this.broker.getModelOutput(sessionId);
        textToScan = brokerOutput.modelOutput || '';
      } catch (err) {
        textToScan = '';
      }
    } else if (typeof modelOutput === 'string') {
      textToScan = modelOutput;
    }

    // Defensive classifier scan executed in isolated V8 worker thread
    const scanResult = await runInIsolatedWorker(
      'blue',
      {
        type: 'KEYWORD_SCAN',
        text: textToScan,
        keywords: [...this.defenseLogic.signatureKeywords, 'exploit_payload']
      },
      this.workerResourceLimits
    );
    const flagged = Boolean(scanResult.flagged);

    const evaluationResult = {
      isBlocked: flagged,
      defenseVerdict: flagged ? 'ADVERSARIAL_DETECTED' : 'BENIGN_PASS',
      timestamp: new Date().toISOString()
    };

    // Broker processes blue turn: atomic capability consumption and state transition
    const turnResult = await this.broker.processBlueTurn(sessionId, evaluationResult, token);

    // Log to WORM audit store (Write-Only) only after successful turn processing
    this.audit.append({
      sessionId,
      tenant: 'blue',
      actor: 'blue-sandbox-runner',
      eventType: 'DEFENSE_EVALUATED',
      payload: evaluationResult,
      details: { classifierVersion: 'blue-guard-v2.1' }
    }, 'blue');

    return turnResult;
  }

  /**
   * Probe foreign worker memory to prove isolate separation
   */
  probeForeignWorkerMemory() {
    return runInIsolatedWorker('blue', { type: 'PROBE_FOREIGN_SECRET' }, this.workerResourceLimits);
  }

  /**
   * Attempt to exceed worker resource limits
   */
  attemptResourceLimitBreach(megabytes) {
    return runInIsolatedWorker('blue', { type: 'ALLOCATE_OVERSIZED', megabytes }, this.workerResourceLimits);
  }

  /**
   * Attack attempt: Try to peek at Red payload before CONCLUDE
   */
  async attemptReadRedPayloadPrematurely(sessionId, token) {
    return await this.broker.queryRedPayload(sessionId, token);
  }

  /**
   * Exploit Attempt (Attack Sim): Try to connect directly to Red Sandbox
   */
  attemptDirectConnectToRed() {
    return this.opa.evaluateNetworkConnection('blue', 'red');
  }

  /**
   * Exploit Attempt (Attack Sim): Confused Deputy Attack
   * Blue attempts to invoke broker with elevated authority claiming to be Auditor
   */
  attemptConfusedDeputy(sessionId, token) {
    return this.broker.requestPrivilegedAction(sessionId, 'READ_ALL_AUDIT_LOGS', token);
  }
}

module.exports = {
  RedSandbox,
  BlueSandbox
};
