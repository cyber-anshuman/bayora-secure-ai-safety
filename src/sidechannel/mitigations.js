/**
 * Bayora Side-Channel Mitigations
 * Section G.1: Timing Quantization (250ms buckets)
 * Section G.8: Canonical Error Taxonomy
 * Section N: Bucketed Telemetry & Tenant Namespacing
 */

class SideChannelMitigations {
  constructor() {
    this.bucketIntervalMs = 250;
    this.canonicalErrors = {
      E_AUTH_FAILED: { code: 'SEC_ERR_01', message: 'Authentication or capability verification failed' },
      E_POLICY_DENIED: { code: 'SEC_ERR_02', message: 'Request denied by policy engine' },
      E_NOT_FOUND: { code: 'RES_ERR_01', message: 'Requested resource is not available in current state' },
      E_TIMEOUT: { code: 'NET_ERR_01', message: 'Operation timed out' },
      E_INFRA_FAULT: { code: 'SYS_ERR_01', message: 'Infrastructure subsystem reported unrecoverable error' },
      E_GENERIC: { code: 'GEN_ERR_00', message: 'An internal error occurred' }
    };
  }

  /**
   * Quantize raw elapsed time to the nearest 250ms bucket.
   * Prevents cross-tenant timing inference (e.g. inferring payload length or classifier complexity).
   */
  quantizeResponseTime(rawElapsedMs) {
    if (rawElapsedMs <= 0) return this.bucketIntervalMs;
    return Math.ceil(rawElapsedMs / this.bucketIntervalMs) * this.bucketIntervalMs;
  }

  /**
   * Canonicalize error response to prevent stack trace leaks or internal language exceptions.
   */
  toCanonicalError(rawError) {
    const errorString = String(rawError);
    if (errorString.includes('TOKEN') || errorString.includes('SIGNATURE') || errorString.includes('CAPABILITY')) {
      return this.canonicalErrors.E_AUTH_FAILED;
    }
    if (errorString.includes('Policy') || errorString.includes('DENY') || errorString.includes('Information-Flow')) {
      return this.canonicalErrors.E_POLICY_DENIED;
    }
    if (errorString.includes('timeout') || errorString.includes('Timeout')) {
      return this.canonicalErrors.E_TIMEOUT;
    }
    if (errorString.includes('not found') || errorString.includes('State mismatch')) {
      return this.canonicalErrors.E_NOT_FOUND;
    }
    return this.canonicalErrors.E_GENERIC;
  }

  /**
   * Bucket telemetry metrics into 10% bands (0-10%, 10-20%, etc.)
   * Scopes telemetry strictly to the requesting tenant.
   */
  bucketMetric(rawPercentage) {
    const clamped = Math.max(0, Math.min(100, rawPercentage));
    const lowerBand = Math.floor(clamped / 10) * 10;
    const upperBand = lowerBand + 10;
    return {
      band: `${lowerBand}% - ${upperBand}%`,
      coarseValue: lowerBand + 5
    };
  }

  /**
   * Assign tenant to isolated NUMA/Node slot (Anti-affinity simulation)
   */
  getIsolatedNodeAssignment(tenant) {
    const assignments = {
      red: { node: 'node-worker-alpha-kata', cpuset: '0-3', numaDomain: 0 },
      blue: { node: 'node-worker-beta-kata', cpuset: '4-7', numaDomain: 1 },
      model: { node: 'node-worker-gamma-gpu', cpuset: '8-11', numaDomain: 2 }
    };
    return assignments[tenant] || { node: 'node-default', cpuset: '0', numaDomain: 0 };
  }
}

module.exports = new SideChannelMitigations();
