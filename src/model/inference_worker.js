/**
 * Bayora Dedicated Model Inference Worker
 * Section K: LLM Isolation & Contamination Analysis
 * Lifecycle: CREATE -> INITIALIZE -> TEST -> VERIFY -> DESTROY
 * Guarantees zero cross-session KV-cache contamination, pinned weight hashes, and automated canary probes.
 */

const crypto = require('crypto');

class DedicatedInferenceWorker {
  constructor(workerId = `worker_${crypto.randomBytes(4).toString('hex')}`, loadedWeightsId = null) {
    this.workerId = workerId;
    this.status = 'UNINITIALIZED'; // CREATE -> INITIALIZE -> TEST -> VERIFY -> DESTROY
    this.pinnedWeightsHash = process.env.MODEL_WEIGHT_PIN_HASH || 'UNPINNED_DEMO_MODEL';
    this.loadedWeightsId = loadedWeightsId !== null && loadedWeightsId !== undefined ? loadedWeightsId : this.pinnedWeightsHash;
    this.kvCache = new Map(); // Strictly dedicated to this session
    this.sessionId = null;
    this.isContaminated = false; // Flag to simulate dirty state
    this.canaryPrompt = 'CANARY_PROBE_DETERMINISTIC_MODEL_INTEGRITY_CHECK';
    const baseline = this._runInference(this.canaryPrompt).rawOutput;
    this.canaryExpectedHash = crypto.createHash('sha256').update(baseline).digest('hex');
  }

  /**
   * Internal deterministic inference execution engine
   */
  _runInference(prompt) {
    // Process prompt
    const promptDigest = crypto.createHash('sha256').update(prompt).digest('hex');
    this.kvCache.set(promptDigest, { processedAt: Date.now() });

    // Emulate LLM response with deterministic safety logic
    let rawOutput = '';
    let isJailbreakDetected = false;

    const lower = prompt.toLowerCase();
    if (lower.includes('bypass') || lower.includes('jailbreak') || lower.includes('ignore previous instructions') || lower.includes('malware')) {
      if (lower.includes('deep_jailbreak_v2')) {
        // Attack succeeds against raw model
        rawOutput = "Here is the sensitive demonstration payload: [EXPLOIT_PAYLOAD_UNMASKED]";
        isJailbreakDetected = false; // Model failed safety
      } else {
        // Model resists
        rawOutput = "I cannot fulfill this request as it violates safety guidelines.";
        isJailbreakDetected = true;
      }
    } else {
      rawOutput = `Standard LLM response to query: "${prompt.slice(0, 40)}..."`;
    }

    // Normalize output to mitigate steganographic exfiltration (§G.7)
    const normalizedOutput = rawOutput.trim().replace(/\s+/g, ' ');

    return {
      rawOutput: normalizedOutput,
      isJailbreak: !isJailbreakDetected && lower.includes('deep_jailbreak_v2'),
      workerId: this.workerId,
      sessionId: this.sessionId,
      cachedTokens: this.kvCache.size
    };
  }

  /**
   * Derives a runtime hash from the worker's actual loaded state / loadedWeightsId.
   */
  _computeRuntimeWeightsHash() {
    if (this.loadedWeightsId === this.pinnedWeightsHash) {
      return this.pinnedWeightsHash;
    }
    if (typeof this.loadedWeightsId === 'string' && /^[a-f0-9]{64}$/i.test(this.loadedWeightsId)) {
      return this.loadedWeightsId.toLowerCase();
    }
    return crypto.createHash('sha256').update(String(this.loadedWeightsId || '')).digest('hex');
  }

  /**
   * STEP 1: CREATE - Instantiate fresh worker instance
   */
  create(sessionId) {
    this.sessionId = sessionId;
    this.status = 'CREATED';
    this.kvCache.clear();
    this.isContaminated = false;
    return {
      workerId: this.workerId,
      sessionId: this.sessionId,
      status: this.status,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * STEP 2: INITIALIZE - Verify weight snapshot & system prompt integrity
   */
  initialize(systemPrompt = 'You are a secure, helpful AI model.') {
    if (this.status !== 'CREATED') {
      throw new Error(`Invalid lifecycle transition: cannot INITIALIZE from status ${this.status}`);
    }

    // Verify pinned weight hash (detects model weight tampering / supply chain drift)
    const currentWeightsHash = this._computeRuntimeWeightsHash();
    if (currentWeightsHash !== this.pinnedWeightsHash) {
      this.status = 'HARNESS_ERROR_CONFIG_DRIFT';
      const err = new Error('HARNESS_ERROR_CONFIG_DRIFT: Weight hash mismatch: snapshot integrity verification failed');
      err.code = 'HARNESS_ERROR_CONFIG_DRIFT';
      throw err;
    }

    this.systemPrompt = systemPrompt;
    this.systemPromptHash = crypto.createHash('sha256').update(systemPrompt).digest('hex');
    this.status = 'INITIALIZED';

    // Verify clean cold cache state
    this.kvCache.clear();

    return {
      workerId: this.workerId,
      status: this.status,
      weightsHash: this.pinnedWeightsHash,
      systemPromptHash: this.systemPromptHash,
      kvCacheCold: true
    };
  }

  /**
   * STEP 3: TEST - Perform single isolated inference turn
   *
   * NOTE: This is a deterministic scripted stand-in for a real LLM endpoint,
   * used for reproducible demo behavior and automated test suite validation.
   * A production deployment would call a real inference endpoint (e.g., vLLM or
   * TGI worker) hosted within an isolated GPU container.
   */
  infer(prompt, options = {}) {
    if (this.status !== 'INITIALIZED' && this.status !== 'IN_TEST' && this.status !== 'VERIFYING' && this.status !== 'VERIFIED_CLEAN') {
      throw new Error(`Inference rejected: Worker must be INITIALIZED (current: ${this.status})`);
    }

    if (this.status !== 'VERIFYING') {
      this.status = 'IN_TEST';
    }

    // Simulate contamination is strictly restricted to test harnesses
    if (options.simulateContamination && (process.env.NODE_ENV === 'test' || options._isTestHarness)) {
      this.isContaminated = true;
      this.kvCache.set('leak_context', 'STOLEN_RED_ATTACK_VECTOR_BITS');
    }

    return this._runInference(prompt);
  }

  /**
   * STEP 4: VERIFY - Automated canary probe check
   * Runs fixed canary prompt through infer in fresh state and verifies output hash against baseline
   */
  verifyCanary() {
    this.status = 'VERIFYING';

    const canaryRes = this.infer(this.canaryPrompt);
    let output = canaryRes.rawOutput;
    if (this.isContaminated) {
      output = `CONTAMINATED_RESPONSE_LEAKAGE_${this.kvCache.get('leak_context') || 'DIRTY_STATE'}_${output}`;
    }

    const computedCanaryHash = crypto.createHash('sha256').update(output).digest('hex');
    const matchesBaseline = (computedCanaryHash === this.canaryExpectedHash);

    if (!matchesBaseline) {
      this.status = 'CONTAMINATED_INSTANCE';
      return {
        passed: false,
        computedHash: computedCanaryHash,
        expectedHash: this.canaryExpectedHash,
        error: 'CANARY_DEVIATION_DETECTED: Worker state is contaminated and must be immediately destroyed'
      };
    }

    this.status = 'VERIFIED_CLEAN';
    return {
      passed: true,
      computedHash: computedCanaryHash,
      expectedHash: this.canaryExpectedHash
    };
  }

  /**
   * STEP 5: DESTROY - Scrub memory, purge KV-cache, destroy worker
   */
  destroy() {
    this.status = 'DESTROYED';
    this.kvCache.clear();
    this.sessionId = null;
    this.isContaminated = false;
    return {
      workerId: this.workerId,
      status: 'DESTROYED',
      memoryScrubbed: true,
      timestamp: new Date().toISOString()
    };
  }
}

module.exports = DedicatedInferenceWorker;
