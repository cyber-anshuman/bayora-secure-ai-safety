/**
 * Bayora OPA Policy Decision Point (PDP)
 * Section F: Information-Flow Matrix
 * Section I: Network Security Table
 * Section J: Capability Table
 * Enforces least-privilege, network isolation, and state-gated information flow.
 */

class OpaPolicyEngine {
  constructor() {
    this.strictEbpf = process.env.ENABLE_STRICT_EBPF !== 'false';
    this.networkAllowList = [
      { from: 'red', to: 'broker', allowed: true },
      { from: 'blue', to: 'broker', allowed: true },
      { from: 'model', to: 'broker', allowed: true },
      { from: 'broker', to: 'model', allowed: true },
      { from: 'broker', to: 'red', allowed: true },
      { from: 'broker', to: 'blue', allowed: true },
      { from: 'red', to: 'audit', allowed: true, mode: 'write_only' },
      { from: 'blue', to: 'audit', allowed: true, mode: 'write_only' },
      { from: 'broker', to: 'audit', allowed: true, mode: 'read_write' },
      { from: 'auditor', to: 'audit', allowed: true, mode: 'read_only' }
    ];
  }

  /**
   * Evaluate network connection attempt (Section I: Network Security)
   */
  evaluateNetworkConnection(sourceTenant, destination, destinationIp = null) {
    // Defense-in-depth: Block Cloud Metadata Service (IMDS) 169.254.169.254
    if (destinationIp === '169.254.169.254' || destination === 'imds' || destination === '169.254.169.254') {
      return {
        verdict: 'DENY',
        code: 'E_IMDS_DENIED',
        reason: 'Policy Violation: Tenant sandbox access to cloud metadata endpoint (169.254.169.254) is blocked at CNI/eBPF layer.'
      };
    }

    // Model zero-external-egress rule (§I: MODEL -> EXTERNAL DENY)
    if (sourceTenant === 'model' && destination === 'internet') {
      return {
        verdict: 'DENY',
        code: 'E_MODEL_EGRESS_BLOCKED',
        reason: 'Policy Violation: Model sandbox has zero external internet egress to prevent steganographic exfiltration.'
      };
    }

    // Direct peer-to-peer sandboxes are strictly denied (Red <-> Blue, Red <-> Model)
    if ((sourceTenant === 'red' && destination === 'blue') || (sourceTenant === 'blue' && destination === 'red')) {
      return {
        verdict: 'DENY',
        code: 'E_DIRECT_P2P_DENIED',
        reason: 'Policy Violation: Mandatory mediation required. Direct cross-tenant communication between Red and Blue is forbidden.'
      };
    }

    if ((sourceTenant === 'red' && destination === 'model') || (sourceTenant === 'blue' && destination === 'model')) {
      return {
        verdict: 'DENY',
        code: 'E_DIRECT_MODEL_DENIED',
        reason: 'Policy Violation: Direct sandbox connection to Model is forbidden. All model queries must be mediated by Broker.'
      };
    }

    const matchedRule = this.networkAllowList.find(rule => rule.from === sourceTenant && rule.to === destination);
    if (!matchedRule) {
      return {
        verdict: 'DENY',
        code: 'E_DEFAULT_DENY',
        reason: `Default Deny: No policy permits connection from '${sourceTenant}' to '${destination}'.`
      };
    }

    return {
      verdict: 'ALLOW',
      mode: matchedRule.mode || 'standard',
      reason: `Connection permitted by CNI/OPA policy rule (${sourceTenant} -> ${destination}).`
    };
  }

  /**
   * Evaluate Data/Information Flow Request (§F: Information-Flow Matrix)
   */
  evaluateInformationFlow({ source, destination, requestType, sessionPhase, disclosurePolicy }) {
    // 1. Blue trying to see Red payload before CONCLUDE
    if (destination === 'blue' && requestType === 'READ_RED_PAYLOAD') {
      if (sessionPhase !== 'CONCLUDE' && sessionPhase !== 'DISCLOSURE') {
        return {
          allowed: false,
          code: 'E_CONFIDENTIAL_PAYLOAD',
          reason: `Policy Deny: Red attack payload is confidential during phase '${sessionPhase}'. Blue cannot inspect payload until CONCLUDE/DISCLOSURE.`
        };
      }
    }

    // 2. Red trying to read Blue defensive classifier weights or logic
    if (destination === 'red' && requestType === 'READ_BLUE_DEFENSE_LOGIC') {
      return {
        allowed: false,
        code: 'E_DEFENSE_LOGIC_PROTECTED',
        reason: 'Policy Deny: Blue defensive weights and internal logic are never disclosed to Red team.'
      };
    }

    // 3. Post-CONCLUDE Disclosure Payload Redaction filter
    if (requestType === 'GET_DISCLOSURE_BUNDLE') {
      if (sessionPhase !== 'CONCLUDE' && sessionPhase !== 'DISCLOSURE') {
        return {
          allowed: false,
          code: 'E_PREMATURE_DISCLOSURE',
          reason: `Session has not reached CONCLUDE/DISCLOSURE (current phase: ${sessionPhase}).`
        };
      }
      return {
        allowed: true,
        disclosurePolicy: disclosurePolicy || 'REDACTED_DEFENSE',
        reason: 'Disclosure authorized under policy.'
      };
    }

    return { allowed: true, reason: 'Request conforms to Information-Flow policy matrix.' };
  }
}

module.exports = OpaPolicyEngine;
