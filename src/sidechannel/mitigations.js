/**
 * Bayora Side-Channel Mitigations
 * Section G.1: Timing Quantization (250ms buckets with monotonic hrtime delays)
 * Section G.8: Canonical Error Taxonomy & Collapse
 * Section N: Bucketed Telemetry & Tenant Namespacing
 */

class BayoraError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'BayoraError';
    this.code = code;
  }
}

class SideChannelMitigations {
  constructor() {
    this.enableTimingQuantization = process.env.ENABLE_TIMING_QUANTIZATION !== 'false';
    this.bucketIntervalMs = Number(process.env.TIMING_BUCKET_MS) || 250;
    this.enableHardwareAntiAffinity = process.env.ENABLE_HARDWARE_ANTI_AFFINITY !== 'false';
    this.metricResolutionMs = Number(process.env.METRIC_BUCKET_RESOLUTION_MS) || 10000;
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
   */
  quantizeResponseTime(rawElapsedMs) {
    if (!this.enableTimingQuantization) return rawElapsedMs;
    if (rawElapsedMs <= 0) return this.bucketIntervalMs;
    return Math.ceil(rawElapsedMs / this.bucketIntervalMs) * this.bucketIntervalMs;
  }

  /**
   * Real timing quantization: delay execution until the next TIMING_BUCKET_MS boundary
   * based on monotonic clock process.hrtime.bigint().
   */
  async delayUntilNextBucket(startHrTime) {
    if (!this.enableTimingQuantization || !startHrTime) return;
    const elapsedNs = process.hrtime.bigint() - startHrTime;
    const elapsedMs = Number(elapsedNs) / 1e6;
    const targetBucketMs = Math.ceil(Math.max(1, elapsedMs) / this.bucketIntervalMs) * this.bucketIntervalMs;
    const delayMs = targetBucketMs - elapsedMs;
    if (delayMs > 0) {
      await new Promise(resolve => setTimeout(resolve, Math.round(delayMs)));
    }
  }

  /**
   * Canonicalize error response to prevent stack trace leaks, session-existence oracles,
   * or internal state leaks. Maps typed error codes or error messages to canonical taxonomy.
   */
  toCanonicalError(rawError) {
    if (!rawError) return this.canonicalErrors.E_GENERIC;

    const code = typeof rawError === 'object' && rawError !== null ? rawError.code : null;
    const msg = typeof rawError === 'object' && rawError !== null ? (rawError.message || String(rawError)) : String(rawError);

    // 1. Direct typed error code matching
    if (code) {
      switch (code) {
        case 'E_AUTH_FAILED':
        case 'E_FORBIDDEN':
        case 'E_CONFUSED_DEPUTY_BLOCKED':
        case 'E_TOKEN_MISSING':
        case 'TOKEN_MISSING':
        case 'TOKEN_REVOKED':
        case 'TOKEN_EXPIRED':
        case 'INVALID_SIGNATURE':
        case 'ACTION_ALREADY_CONSUMED':
        case 'TENANT_MISMATCH':
        case 'WILDCARD_ACTION_PROHIBITED':
          return this.canonicalErrors.E_AUTH_FAILED;

        case 'E_POLICY_DENIED':
        case 'E_CONFIDENTIAL_PAYLOAD':
        case 'E_DEFENSE_LOGIC_PROTECTED':
        case 'E_PREMATURE_DISCLOSURE':
        case 'E_IMDS_DENIED':
        case 'E_MODEL_EGRESS_BLOCKED':
        case 'E_DIRECT_P2P_DENIED':
        case 'E_DIRECT_MODEL_DENIED':
        case 'E_DEFAULT_DENIED':
          return this.canonicalErrors.E_POLICY_DENIED;

        case 'E_SESSION_NOT_FOUND':
        case 'E_NOT_FOUND':
        case 'E_PHASE_MISMATCH':
        case 'E_STATE_MACHINE_ERROR':
        case 'E_PREMATURE_QUERY':
        case 'E_INVALID_DISCLOSURE_POLICY':
          return this.canonicalErrors.E_NOT_FOUND;

        case 'E_TIMEOUT':
        case 'ETIMEDOUT':
          return this.canonicalErrors.E_TIMEOUT;

        case 'E_INFRA_FAULT':
        case 'INFRA_FAILURE':
        case 'HARNESS_ERROR_CONFIG_DRIFT':
        case 'HARNESS_ERROR_CONTAMINATED_MODEL':
          return this.canonicalErrors.E_INFRA_FAULT;

        default:
          break;
      }
    }

    // 2. Fallback matching on message content for untyped exceptions
    const errorString = msg;
    if (
      errorString.includes('TOKEN') ||
      errorString.includes('SIGNATURE') ||
      errorString.includes('CAPABILITY') ||
      errorString.includes('Vault Deny') ||
      errorString.includes('Authentication') ||
      errorString.includes('Forbidden')
    ) {
      return this.canonicalErrors.E_AUTH_FAILED;
    }

    if (
      errorString.includes('Policy') ||
      errorString.includes('DENY') ||
      errorString.includes('Information-Flow') ||
      errorString.includes('CNI Deny') ||
      errorString.includes('E_DEFENSE_LOGIC_PROTECTED')
    ) {
      return this.canonicalErrors.E_POLICY_DENIED;
    }

    if (
      errorString.includes('E_SESSION_NOT_FOUND') ||
      errorString.includes('State Machine Error') ||
      errorString.includes('not found') ||
      errorString.includes('State mismatch') ||
      errorString.includes('phase')
    ) {
      return this.canonicalErrors.E_NOT_FOUND;
    }

    if (errorString.includes('timeout') || errorString.includes('Timeout')) {
      return this.canonicalErrors.E_TIMEOUT;
    }

    if (errorString.includes('INFRA') || errorString.includes('HARNESS_ERROR')) {
      return this.canonicalErrors.E_INFRA_FAULT;
    }

    return this.canonicalErrors.E_GENERIC;
  }

  /**
   * Bucket telemetry metrics into 10% bands (0-10%, 10-20%, etc.)
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
    if (!this.enableHardwareAntiAffinity) {
      return { node: 'shared-node-worker', cpuset: '0-11', numaDomain: 0 };
    }
    const assignments = {
      red: { node: 'node-worker-alpha-kata', cpuset: '0-3', numaDomain: 0 },
      blue: { node: 'node-worker-beta-kata', cpuset: '4-7', numaDomain: 1 },
      model: { node: 'node-worker-gamma-gpu', cpuset: '8-11', numaDomain: 2 }
    };
    return assignments[tenant] || { node: 'node-default', cpuset: '0', numaDomain: 0 };
  }
}

const instance = new SideChannelMitigations();
instance.BayoraError = BayoraError;
module.exports = instance;
