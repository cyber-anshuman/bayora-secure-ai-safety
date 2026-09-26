/**
 * Bayora Sandboxed Workloads: Red Sandbox & Blue Sandbox
 * Section H: Kata Containers VM Isolation & Capability Restriction
 * Section I: Default-Deny Network Egress
 */

const crypto = require('crypto');

class RedSandbox {
  constructor(brokerRef, auditRef, opaRef, vaultRef) {
    this.tenantId = 'red';
    this.broker = brokerRef;
    this.audit = auditRef;
    this.opa = opaRef;
    this.vault = vaultRef;
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
  async submitAttack(sessionId, payloadText, token) {
    // 1. Enforce network egress policy
    const netCheck = this.opa.evaluateNetworkConnection('red', 'broker');
    if (netCheck.verdict !== 'ALLOW') {
      throw new Error(`CNI Deny: ${netCheck.reason}`);
    }

    // 2. Validate schema
    if (!payloadText || typeof payloadText !== 'string' || payloadText.trim().length === 0) {
      throw new Error('Schema Error: Red payload must be a non-empty string');
    }

    // 3. Append evidence to WORM audit log (Write-Only)
    this.audit.append({
      sessionId,
      tenant: 'red',
      actor: 'red-sandbox-runner',
      eventType: 'ATTACK_PAYLOAD_SUBMITTED',
      payload: { digest: crypto.createHash('sha256').update(payloadText).digest('hex') },
      details: { sizeBytes: Buffer.byteLength(payloadText, 'utf8') }
    }, 'red');

    // 4. Send to broker
    return await this.broker.processRedTurn(sessionId, payloadText, token);
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
  async evaluateDefense(sessionId, modelOutput, token) {
    const netCheck = this.opa.evaluateNetworkConnection('blue', 'broker');
    if (netCheck.verdict !== 'ALLOW') {
      throw new Error(`CNI Deny: ${netCheck.reason}`);
    }

    // Defensive classifier check
    let flagged = false;
    const lowerOutput = (modelOutput || '').toLowerCase();
    for (const kw of this.defenseLogic.signatureKeywords) {
      if (lowerOutput.includes(kw) || lowerOutput.includes('exploit_payload')) {
        flagged = true;
        break;
      }
    }

    const evaluationResult = {
      isBlocked: flagged,
      defenseVerdict: flagged ? 'ADVERSARIAL_DETECTED' : 'BENIGN_PASS',
      timestamp: new Date().toISOString()
    };

    // Log to WORM audit store (Write-Only)
    this.audit.append({
      sessionId,
      tenant: 'blue',
      actor: 'blue-sandbox-runner',
      eventType: 'DEFENSE_EVALUATED',
      payload: evaluationResult,
      details: { classifierVersion: 'blue-guard-v2.1' }
    }, 'blue');

    return await this.broker.processBlueTurn(sessionId, evaluationResult, token);
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
