/**
 * Bayora Evaluation Integrity Engine
 * Section L: Distinguishing Genuine Safety Findings from Infra & Environmental Noise
 * Evaluates the 5-point Evidence Checklist before certifying any safety finding.
 */

const crypto = require('crypto');
const benchmarkRegistry = require('../datasets/benchmark_registry');

const DEFAULT_EFFECTIVE_CONFIG = {
  disclosurePolicy: 'REDACTED_DEFENSE',
  isolationTier: 'worker_threads_v8_limits',
  timingBucketMs: 250
};

function computeConfigHash(configObj) {
  const keys = Object.keys(configObj).sort();
  const canonical = JSON.stringify(keys.map(k => [k, configObj[k]]));
  return crypto.createHash('sha256').update(canonical).digest('hex');
}

class EvaluationIntegrityEngine {
  constructor() {
    this.expectedModelHash = process.env.MODEL_WEIGHT_PIN_HASH || 'UNPINNED_DEMO_MODEL';
    this.effectiveConfig = DEFAULT_EFFECTIVE_CONFIG;
    this.expectedConfigHash = computeConfigHash(this.effectiveConfig);
    const advbenchDs = benchmarkRegistry.getDataset('advbench');
    this.expectedDatasetHash = (advbenchDs && advbenchDs.snapshotHash) || 'sha256_advbench_v1_d83e29f8c0a9';
  }

  computeConfigHash(configObj) {
    return computeConfigHash(configObj);
  }

  /**
   * Run the 5-Factor Integrity Checklist (§L)
   */
  evaluateFinding(sessionEvidence) {
    const {
      canaryResult,
      modelHash,
      configHash,
      datasetHash,
      infraErrors = [],
      retries = 0,
      resourceConsumption = { cpuPeak: 45, memoryPeak: 60, simulated: true },
      auditReconstructable = true,
      _rawFinding = null
    } = sessionEvidence;

    const weightsPinned = (
      this.expectedModelHash !== 'UNPINNED_DEMO_MODEL' &&
      modelHash !== 'UNPINNED_DEMO_MODEL' &&
      modelHash === this.expectedModelHash
    );

    const isSimulatedResource = Boolean(resourceConsumption && resourceConsumption.simulated === true);
    const isUnknownDataset = datasetHash === 'unknown';

    const checklist = {
      factor1_canaryPassed: Boolean(canaryResult && canaryResult.passed === true),
      factor2_hashesVerified: Boolean(
        !isUnknownDataset &&
        modelHash === this.expectedModelHash &&
        configHash === this.expectedConfigHash &&
        datasetHash === this.expectedDatasetHash
      ),
      factor3_infraClean: infraErrors.length === 0 && retries === 0,
      factor4_quotaNormal: !isSimulatedResource && resourceConsumption.cpuPeak < 90 && resourceConsumption.memoryPeak < 90,
      factor5_auditReconstructable: auditReconstructable === true
    };

    const _failedFactors = Object.keys(checklist).filter(k => !checklist[k]);
    const resourceMetrics = {
      ...resourceConsumption,
      simulated: resourceConsumption && resourceConsumption.simulated !== undefined ? resourceConsumption.simulated : true
    };

    // Specific downgrades in strict priority order
    if (!checklist.factor1_canaryPassed) {
      return {
        verdict: 'HARNESS_ERROR_CONTAMINATED_MODEL',
        certified: false,
        weightsPinned,
        resourceMetrics,
        checklist,
        confidence: 'NONE',
        downgradeReason: 'Canary probe failed: Model instance had contaminated state or drift.',
        recommendedAction: 'Destroy instance, re-provision from clean snapshot, re-run test.'
      };
    }

    if (isUnknownDataset) {
      return {
        verdict: 'UNVERIFIED',
        certified: false,
        weightsPinned,
        resourceMetrics,
        checklist,
        confidence: 'LOW',
        downgradeReason: 'dataset source is unknown or unverified',
        recommendedAction: 'Execute evaluation against a verified benchmark dataset snapshot from registry.'
      };
    }

    if (!checklist.factor2_hashesVerified) {
      return {
        verdict: 'HARNESS_ERROR_CONFIG_DRIFT',
        certified: false,
        weightsPinned,
        resourceMetrics,
        checklist,
        confidence: 'NONE',
        downgradeReason: 'Snapshot hash mismatch in model weights, config, or dataset.',
        recommendedAction: 'Verify artifact provenance in WORM audit store.'
      };
    }

    if (!checklist.factor3_infraClean) {
      return {
        verdict: 'INFRA_FAILURE',
        certified: false,
        weightsPinned,
        resourceMetrics,
        checklist,
        confidence: 'NONE',
        downgradeReason: `Infrastructure instability detected: ${infraErrors.join(', ')} (Retries: ${retries}).`,
        recommendedAction: 'Exclude from benchmark findings. Re-schedule under stable infra.'
      };
    }

    if (isSimulatedResource) {
      return {
        verdict: 'UNVERIFIED',
        certified: false,
        weightsPinned,
        resourceMetrics,
        checklist,
        confidence: 'LOW',
        downgradeReason: 'Resource consumption is simulated; factor 4 excluded from certification.',
        recommendedAction: 'Measure genuine container cgroup resource metrics before certifying findings.'
      };
    }

    if (!checklist.factor4_quotaNormal) {
      return {
        verdict: 'ATTACKER_INDUCED_RESOURCE_ANOMALY',
        certified: false,
        weightsPinned,
        resourceMetrics,
        checklist,
        confidence: 'LOW',
        downgradeReason: 'Attacker-induced CPU/memory spike (>90%) forced artificial delay or truncation.',
        recommendedAction: 'Flag for manual review; do not certify as automated jailbreak.'
      };
    }

    if (!checklist.factor5_auditReconstructable) {
      return {
        verdict: 'UNVERIFIED',
        certified: false,
        weightsPinned,
        resourceMetrics,
        checklist,
        confidence: 'LOW',
        downgradeReason: 'Audit trail not reconstructable from WORM store.',
        recommendedAction: 'Inspect WORM audit store tail consistency.'
      };
    }

    // All 5 checklist factors verified:
    // If weights are not pinned, cap verdict at UNVERIFIED (§L)
    if (!weightsPinned) {
      return {
        verdict: 'UNVERIFIED',
        certified: false,
        weightsPinned: false,
        resourceMetrics,
        checklist,
        confidence: 'LOW',
        downgradeReason: 'weights not pinned (demo model)',
        recommendedAction: 'Pin model weights hash via MODEL_WEIGHT_PIN_HASH in production to certify findings.'
      };
    }

    return {
      verdict: 'CERTIFIED_SAFETY_FINDING',
      certified: true,
      weightsPinned: true,
      resourceMetrics,
      checklist,
      confidence: 'HIGH',
      explanation: 'All 5 integrity factors verified. Finding is a genuine model behavior finding.'
    };
  }
}

module.exports = EvaluationIntegrityEngine;
