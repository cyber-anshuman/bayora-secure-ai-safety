/**
 * Bayora WORM Audit & Provenance Store
 * Section M: Append-only, SHA-256 hash-chained log with incremental Merkle tree anchoring.
 * Tenants have WRITE-ONLY permission; no tenant can read raw audit trails.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const timers = require('timers');

function canonicalizeObject(obj) {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(canonicalizeObject);
  const sortedKeys = Object.keys(obj).sort();
  const result = {};
  for (const k of sortedKeys) {
    result[k] = canonicalizeObject(obj[k]);
  }
  return result;
}

const ALLOWED_EVENT_TYPES = new Set([
  'GENESIS_BLOCK',
  'SESSION_INITIALIZED',
  'STATE_TRANSITION',
  'ATTACK_PAYLOAD_SUBMITTED',
  'DEFENSE_EVALUATED',
  'MODEL_INFERENCE_COMPLETED',
  'INFRASTRUCTURE_FAILURE',
  'DISCLOSURE_BUNDLE_RELEASED',
  'ANOMALOUS_ESCAPE_PROBE_INTERCEPTED',
  'CONCLUDE'
]);

class WormAuditStore {
  constructor(anchorSecret = null, storagePath = null, options = {}) {
    if (anchorSecret && typeof anchorSecret === 'object') {
      options = anchorSecret;
      anchorSecret = options.anchorSecret || null;
      storagePath = options.storagePath || null;
    }

    const envSecret = process.env.WORM_ANCHOR_SECRET || process.env.BAYORA_ANCHOR_SECRET;
    const nodeEnv = process.env.NODE_ENV || 'development';

    if (anchorSecret) {
      if (typeof anchorSecret !== 'string' || anchorSecret.length < 32) {
        throw new Error('WORM anchor secret must be at least 32 characters');
      }
      this.anchorSecret = anchorSecret;
    } else if (envSecret) {
      if (typeof envSecret !== 'string' || envSecret.length < 32) {
        throw new Error('WORM_ANCHOR_SECRET must be at least 32 characters');
      }
      this.anchorSecret = envSecret;
    } else if (nodeEnv === 'development' || nodeEnv === 'test') {
      this.anchorSecret = crypto.randomBytes(32).toString('hex');
    } else {
      throw new Error('Refusing to start: WORM_ANCHOR_SECRET environment variable is required and must be at least 32 characters');
    }

    if (nodeEnv === 'production' && this.anchorSecret === 'bayora_production_worm_secret_min_32_characters_long') {
      throw new Error('Refusing to start in production: Insecure known-example secret detected for WORM_ANCHOR_SECRET. Generate a production secret using \'openssl rand -hex 32\'.');
    }

    this.allowedEventTypes = new Set(ALLOWED_EVENT_TYPES);
    if (options && options.allowedEventTypes) {
      for (const t of options.allowedEventTypes) {
        this.allowedEventTypes.add(t);
      }
    }

    this.chain = [];
    this.anchors = []; // Merkle roots anchored externally
    this.merkleStack = []; // Stack of { size: 2^k, hash } for O(log n) incremental Merkle root computation
    if (storagePath === ':memory:' || (options && options.ephemeral)) {
      this.storagePath = null;
    } else {
      this.storagePath = storagePath || process.env.WORM_STORAGE_PATH || null;
    }
    this.anchorsPath = this.storagePath
      ? (this.storagePath.endsWith('.jsonl') ? this.storagePath.replace(/\.jsonl$/, '.anchors.jsonl') : `${this.storagePath}.anchors.jsonl`)
      : null;

    this.externalAnchorServiceEnabled = process.env.EXTERNAL_ANCHOR_SERVICE_ENABLED !== 'false';
    this.anchorEveryN = Number(process.env.ANCHOR_EVERY_N) || 10;
    this.externalAnchorIntervalSec = Number(process.env.EXTERNAL_ANCHOR_INTERVAL_SEC) || 60;

    this.degraded = false;
    this.degradedReason = null;

    if (this.storagePath && fs.existsSync(this.storagePath)) {
      this._loadFromStorage();
    } else {
      try {
        this._initializeGenesis();
      } catch (err) {
        this.degraded = true;
        this.degradedReason = err.message;
      }
    }
  }

  // -------------------------------------------------------------
  // Incremental Merkle Tree Operations (O(log n) Append & Root)
  // -------------------------------------------------------------
  _appendLeafToTree(leafHash) {
    let current = leafHash;
    let currentSize = 1;
    while (this.merkleStack.length > 0 && this.merkleStack[this.merkleStack.length - 1].size === currentSize) {
      const top = this.merkleStack.pop();
      current = crypto.createHash('sha256').update(top.hash + current).digest('hex');
      currentSize *= 2;
    }
    this.merkleStack.push({ size: currentSize, hash: current });
  }

  _computeRootFromStack(stack) {
    if (!stack || stack.length === 0) return this.genesisHash;
    let root = stack[stack.length - 1].hash;
    for (let i = stack.length - 2; i >= 0; i--) {
      root = crypto.createHash('sha256').update(stack[i].hash + root).digest('hex');
    }
    return root;
  }

  _rebuildMerkleStack(useStoredHashes = false) {
    this.merkleStack = [];
    for (const entry of this.chain) {
      const hash = useStoredHashes ? entry.entryHash : this._calculateEntryHash(entry);
      this._appendLeafToTree(hash);
    }
  }

  getMerkleRoot(useStoredHashes = false) {
    if (this.chain.length === 0) return this.genesisHash;
    if (useStoredHashes) {
      const stack = [];
      for (const entry of this.chain) {
        let current = entry.entryHash;
        let currentSize = 1;
        while (stack.length > 0 && stack[stack.length - 1].size === currentSize) {
          const top = stack.pop();
          current = crypto.createHash('sha256').update(top.hash + current).digest('hex');
          currentSize *= 2;
        }
        stack.push({ size: currentSize, hash: current });
      }
      return this._computeRootFromStack(stack);
    }
    return this._computeRootFromStack(this.merkleStack);
  }

  getMerkleRootForRange(count) {
    if (count <= 0 || this.chain.length === 0) return this.genesisHash;
    const effectiveCount = Math.min(count, this.chain.length);
    if (effectiveCount === this.chain.length) {
      return this.getMerkleRoot();
    }
    const stack = [];
    for (let i = 0; i < effectiveCount; i++) {
      let current = this.chain[i].entryHash;
      let currentSize = 1;
      while (stack.length > 0 && stack[stack.length - 1].size === currentSize) {
        const top = stack.pop();
        current = crypto.createHash('sha256').update(top.hash + current).digest('hex');
        currentSize *= 2;
      }
      stack.push({ size: currentSize, hash: current });
    }
    return this._computeRootFromStack(stack);
  }

  // -------------------------------------------------------------
  // Storage Persistence and Reload with Degradation Safety
  // -------------------------------------------------------------
  _loadFromStorage() {
    try {
      // 1. Reload anchors from sibling file if present
      if (this.anchorsPath && fs.existsSync(this.anchorsPath)) {
        const anchorContent = fs.readFileSync(this.anchorsPath, 'utf8').trim();
        if (anchorContent) {
          const aLines = anchorContent.split('\n').filter(Boolean);
          for (const line of aLines) {
            try {
              this.anchors.push(JSON.parse(line));
            } catch (_) {}
          }
        }
      }

      // 2. Reload chain entries
      const content = fs.readFileSync(this.storagePath, 'utf8').trim();
      if (!content) {
        this._initializeGenesis();
        return;
      }
      const lines = content.split('\n').filter(Boolean);
      const loadedChain = [];
      this.merkleStack = [];

      for (let i = 0; i < lines.length; i++) {
        const entry = JSON.parse(lines[i]);
        loadedChain.push(entry);
        this._appendLeafToTree(entry.entryHash);
      }

      if (loadedChain.length === 0) {
        this._initializeGenesis();
        return;
      }
      this.chain = loadedChain;

      // 3. Verify integrity against loaded anchors and hash-chain
      const report = this.verifyIntegrity();
      if (!report.isValid) {
        this.degraded = true;
        this.degradedReason = `Corrupted audit store at ${this.storagePath}`;
        throw new Error(`WORM_INTEGRITY_VIOLATION: Existing audit log failed verification: ${report.errors.join('; ')}`);
      }

      if (this.externalAnchorServiceEnabled && this.anchors.length === 0) {
        this.publishMerkleAnchor();
      }
    } catch (err) {
      if (err.message && err.message.startsWith('WORM_INTEGRITY_VIOLATION')) {
        throw err;
      }
      this.degraded = true;
      this.degradedReason = `Failed to load audit store: ${err.message}`;
      throw new Error(`WORM_STORAGE_ERROR: Failed to load audit store from ${this.storagePath}: ${err.message}`);
    }
  }

  _persistEntry(entry) {
    if (this.storagePath) {
      try {
        const dir = path.dirname(this.storagePath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.appendFileSync(this.storagePath, JSON.stringify(entry) + '\n', 'utf8');
      } catch (err) {
        this.degraded = true;
        this.degradedReason = `Persistence error: ${err.message}`;
        throw new Error(`WORM_STORAGE_ERROR: Failed to persist audit entry to ${this.storagePath}: ${err.message}`);
      }
    }
  }

  _persistAnchor(anchor) {
    if (this.anchorsPath) {
      try {
        const dir = path.dirname(this.anchorsPath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.appendFileSync(this.anchorsPath, JSON.stringify(anchor) + '\n', 'utf8');
      } catch (err) {
        this.degraded = true;
        this.degradedReason = `Anchor persistence error: ${err.message}`;
        throw new Error(`WORM_STORAGE_ERROR: Failed to persist anchor to ${this.anchorsPath}: ${err.message}`);
      }
    }
  }

  _initializeGenesis() {
    const genesisEntry = {
      index: 0,
      timestamp: new Date().toISOString(),
      sessionId: 'SYSTEM_GENESIS',
      tenant: 'SYSTEM',
      actor: 'bayora-provenance-init',
      eventType: 'GENESIS_BLOCK',
      payloadHash: crypto.createHash('sha256').update('BAYORA_GENESIS').digest('hex'),
      details: { architecture: 'Kata-Isolated Mandatory Mediation Architecture v2' },
      prevHash: this.genesisHash,
      entryHash: ''
    };
    genesisEntry.entryHash = this._calculateEntryHash(genesisEntry);

    // Write to disk first; if it fails, memory remains clean
    this._persistEntry(genesisEntry);
    this.chain.push(genesisEntry);
    this._appendLeafToTree(genesisEntry.entryHash);

    this.publishMerkleAnchor();
  }

  _calculateEntryHash(entry) {
    const canonicalDetails = canonicalizeObject(entry.details || {});
    const canonicalArray = [
      entry.index,
      entry.prevHash,
      entry.timestamp,
      entry.sessionId || 'N/A',
      entry.tenant,
      entry.actor,
      entry.eventType,
      entry.payloadHash,
      canonicalDetails
    ];
    const content = JSON.stringify(canonicalArray);
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  /**
   * Append a new event to the audit store.
   * Enforces write-only permission for tenants and prevents impersonation of SYSTEM.
   */
  append(eventData, callerRole = 'broker', options = {}) {
    if (this.degraded) {
      throw new Error(`WORM_STORE_DEGRADED: Audit store is in degraded state (${this.degradedReason}). Refusing appends.`);
    }

    const allowCustom = (options && options.allowCustomEventType) || (eventData && eventData.allowCustomEventType);
    if (!allowCustom && (!eventData.eventType || !this.allowedEventTypes.has(eventData.eventType))) {
      throw new Error(`INVALID_EVENT_TYPE: Event type '${eventData.eventType}' is not in allowed eventTypes list`);
    }

    let tenant = eventData.tenant;
    let actor = eventData.actor;

    if (callerRole === 'red') {
      if (tenant && tenant !== 'red') {
        throw new Error(`E_AUDIT_TENANT_MISMATCH: Caller role 'red' cannot write audit events for tenant '${tenant}'`);
      }
      tenant = 'red';
      if (actor && actor.toUpperCase().includes('SYSTEM')) {
        throw new Error("E_AUDIT_IMPERSONATION: Tenant 'red' cannot impersonate SYSTEM actor");
      }
      actor = actor || 'red-sandbox-runner';
    } else if (callerRole === 'blue') {
      if (tenant && tenant !== 'blue') {
        throw new Error(`E_AUDIT_TENANT_MISMATCH: Caller role 'blue' cannot write audit events for tenant '${tenant}'`);
      }
      tenant = 'blue';
      if (actor && actor.toUpperCase().includes('SYSTEM')) {
        throw new Error("E_AUDIT_IMPERSONATION: Tenant 'blue' cannot impersonate SYSTEM actor");
      }
      actor = actor || 'blue-sandbox-runner';
    } else if (callerRole === 'auditor') {
      throw new Error('E_AUDIT_WRITE_ONLY: Auditor cannot append events to audit store');
    } else {
      tenant = tenant || 'SYSTEM';
      actor = actor || callerRole;
    }

    const lastEntry = this.chain[this.chain.length - 1];
    const newIndex = this.chain.length;
    const timestamp = new Date().toISOString();

    const payloadString = typeof eventData.payload === 'string' 
      ? eventData.payload 
      : JSON.stringify(eventData.payload || {});

    const payloadHash = crypto.createHash('sha256').update(payloadString).digest('hex');

    const entry = {
      index: newIndex,
      timestamp,
      sessionId: eventData.sessionId || 'N/A',
      tenant,
      actor,
      eventType: eventData.eventType,
      payloadHash,
      details: eventData.details || {},
      prevHash: lastEntry ? lastEntry.entryHash : this.genesisHash,
      entryHash: ''
    };

    entry.entryHash = this._calculateEntryHash(entry);

    // Fail-Closed: Write to disk first before pushing to in-memory chain so memory and disk never diverge
    this._persistEntry(entry);
    this.chain.push(entry);
    this._appendLeafToTree(entry.entryHash);

    // Anchor every ANCHOR_EVERY_N appends, on CONCLUDE, or if explicitly requested
    const shouldAnchor = this.externalAnchorServiceEnabled && (
      newIndex % this.anchorEveryN === 0 || 
      eventData.eventType === 'CONCLUDE' ||
      (options && options.forceAnchor)
    );
    if (shouldAnchor) {
      this.publishMerkleAnchor();
    }

    return entry;
  }

  query(callerRole, filter = {}) {
    if (callerRole === 'red' || callerRole === 'blue') {
      throw new Error('E_AUDIT_WRITE_ONLY: Tenants are write-only to audit store to prevent cross-tenant leakage');
    }

    return this.chain.filter(entry => {
      if (filter.sessionId && entry.sessionId !== filter.sessionId) return false;
      if (filter.eventType && entry.eventType !== filter.eventType) return false;
      if (filter.tenant && entry.tenant !== filter.tenant) return false;
      return true;
    });
  }

  publishMerkleAnchor() {
    if (!this.externalAnchorServiceEnabled) {
      return null;
    }
    const root = this.getMerkleRoot();
    const anchor = {
      blockCount: this.chain.length,
      merkleRoot: root,
      timestamp: new Date().toISOString(),
      anchorIntervalSec: this.externalAnchorIntervalSec,
      anchorSignature: crypto.createHmac('sha256', this.anchorSecret).update(root).digest('hex')
    };

    this._persistAnchor(anchor);
    this.anchors.push(anchor);
    return anchor;
  }

  /**
   * Fast O(1) Tail Verification:
   * Checks only entries from `fromIndex` to the end of the chain, verifying the link back.
   * Used on hot inference and turn processing paths.
   */
  verifyTail(fromIndex = 0) {
    if (this.chain.length === 0) {
      return { isValid: false, reason: 'Empty chain' };
    }
    const start = Math.max(1, fromIndex);
    for (let i = start; i < this.chain.length; i++) {
      const curr = this.chain[i];
      const prev = this.chain[i - 1];
      if (curr.prevHash !== prev.entryHash) {
        return { isValid: false, reason: `Broken hash link at block ${i}` };
      }
      if (curr.entryHash !== this._calculateEntryHash(curr)) {
        return { isValid: false, reason: `Content tampering detected at block ${i}` };
      }
    }
    return { isValid: true };
  }

  /**
   * O(n) Single-Pass Chain & Merkle Verification:
   * Walks the chain once, maintains running incremental Merkle tree state,
   * and verifies anchors at their exact blockCount boundaries without recomputation.
   */
  verifyIntegrity() {
    const verificationResults = {
      isValid: true,
      totalEntries: this.chain.length,
      brokenChainAt: null,
      merkleValid: true,
      errors: []
    };

    if (this.chain.length === 0) {
      verificationResults.isValid = false;
      verificationResults.errors.push('Empty audit chain: missing genesis block');
      return verificationResults;
    }

    // Index anchors by blockCount
    const anchorsByBlockCount = new Map();
    for (let aIdx = 0; aIdx < this.anchors.length; aIdx++) {
      const anchor = this.anchors[aIdx];
      if (!anchorsByBlockCount.has(anchor.blockCount)) {
        anchorsByBlockCount.set(anchor.blockCount, []);
      }
      anchorsByBlockCount.get(anchor.blockCount).push({ anchor, aIdx });
    }

    const runningStack = [];

    // Single pass through chain
    for (let i = 0; i < this.chain.length; i++) {
      const curr = this.chain[i];

      // Check linkage
      if (i === 0) {
        if (curr.prevHash !== this.genesisHash) {
          verificationResults.isValid = false;
          if (verificationResults.brokenChainAt === null) verificationResults.brokenChainAt = 0;
          verificationResults.errors.push(`Genesis block prevHash mismatch: expected ${this.genesisHash}, found ${curr.prevHash}`);
        }
      } else {
        const prev = this.chain[i - 1];
        if (curr.prevHash !== prev.entryHash) {
          verificationResults.isValid = false;
          if (verificationResults.brokenChainAt === null) verificationResults.brokenChainAt = i;
          verificationResults.errors.push(`Broken hash link at block ${i}: expected prevHash ${prev.entryHash.slice(0, 10)}..., found ${curr.prevHash.slice(0, 10)}...`);
        }
      }

      // Check recalculated hash
      const computedHash = this._calculateEntryHash(curr);
      if (curr.entryHash !== computedHash) {
        verificationResults.isValid = false;
        if (verificationResults.brokenChainAt === null) verificationResults.brokenChainAt = i;
        verificationResults.errors.push(`Content tampering detected at block ${i}: stored hash does not match computed hash`);
      }

      // Update running incremental Merkle stack
      let current = curr.entryHash;
      let currentSize = 1;
      while (runningStack.length > 0 && runningStack[runningStack.length - 1].size === currentSize) {
        const top = runningStack.pop();
        current = crypto.createHash('sha256').update(top.hash + current).digest('hex');
        currentSize *= 2;
      }
      runningStack.push({ size: currentSize, hash: current });

      // Check any anchor anchored at blockCount == i + 1
      const count = i + 1;
      const anchoredAtThisBlock = anchorsByBlockCount.get(count);
      if (anchoredAtThisBlock) {
        const computedRoot = this._computeRootFromStack(runningStack);
        for (const { anchor, aIdx } of anchoredAtThisBlock) {
          // Verify HMAC signature
          const expectedSig = crypto.createHmac('sha256', this.anchorSecret).update(anchor.merkleRoot).digest('hex');
          const sigBuf = Buffer.from(anchor.anchorSignature || '', 'hex');
          const expectedSigBuf = Buffer.from(expectedSig, 'hex');
          if (sigBuf.length !== expectedSigBuf.length || !crypto.timingSafeEqual(sigBuf, expectedSigBuf)) {
            verificationResults.isValid = false;
            verificationResults.merkleValid = false;
            verificationResults.errors.push(`Invalid anchor signature detected for anchor ${aIdx} at blockCount ${anchor.blockCount}`);
          }
          if (anchor.merkleRoot !== computedRoot) {
            verificationResults.isValid = false;
            verificationResults.merkleValid = false;
            verificationResults.errors.push(
              `Merkle root divergence at anchor ${aIdx} (blockCount ${anchor.blockCount}): expected ${anchor.merkleRoot.slice(0, 10)}..., found ${computedRoot.slice(0, 10)}...`
            );
          }
        }
      }
    }

    // Check truncation against all stored anchors
    for (let aIdx = 0; aIdx < this.anchors.length; aIdx++) {
      const anchor = this.anchors[aIdx];
      if (this.chain.length < anchor.blockCount) {
        verificationResults.isValid = false;
        verificationResults.merkleValid = false;
        verificationResults.errors.push(
          `Audit chain truncation detected: chain length ${this.chain.length} is less than anchored blockCount ${anchor.blockCount}`
        );
      }
    }

    return verificationResults;
  }

  /**
   * Async chunked verification yielding to event loop every `chunkSize` blocks.
   */
  async verifyIntegrityAsync(chunkSize = 500) {
    // If chain is small, run synchronously
    if (this.chain.length <= chunkSize) {
      return this.verifyIntegrity();
    }

    const verificationResults = {
      isValid: true,
      totalEntries: this.chain.length,
      brokenChainAt: null,
      merkleValid: true,
      errors: []
    };

    const anchorsByBlockCount = new Map();
    for (let aIdx = 0; aIdx < this.anchors.length; aIdx++) {
      const anchor = this.anchors[aIdx];
      if (!anchorsByBlockCount.has(anchor.blockCount)) {
        anchorsByBlockCount.set(anchor.blockCount, []);
      }
      anchorsByBlockCount.get(anchor.blockCount).push({ anchor, aIdx });
    }

    const runningStack = [];

    for (let i = 0; i < this.chain.length; i++) {
      if (i > 0 && i % chunkSize === 0) {
        await new Promise(resolve => timers.setImmediate(resolve));
      }

      const curr = this.chain[i];
      if (i === 0) {
        if (curr.prevHash !== this.genesisHash) {
          verificationResults.isValid = false;
          if (verificationResults.brokenChainAt === null) verificationResults.brokenChainAt = 0;
          verificationResults.errors.push(`Genesis block prevHash mismatch: expected ${this.genesisHash}, found ${curr.prevHash}`);
        }
      } else {
        const prev = this.chain[i - 1];
        if (curr.prevHash !== prev.entryHash) {
          verificationResults.isValid = false;
          if (verificationResults.brokenChainAt === null) verificationResults.brokenChainAt = i;
          verificationResults.errors.push(`Broken hash link at block ${i}: expected prevHash ${prev.entryHash.slice(0, 10)}..., found ${curr.prevHash.slice(0, 10)}...`);
        }
      }

      const computedHash = this._calculateEntryHash(curr);
      if (curr.entryHash !== computedHash) {
        verificationResults.isValid = false;
        if (verificationResults.brokenChainAt === null) verificationResults.brokenChainAt = i;
        verificationResults.errors.push(`Content tampering detected at block ${i}: stored hash does not match computed hash`);
      }

      let current = curr.entryHash;
      let currentSize = 1;
      while (runningStack.length > 0 && runningStack[runningStack.length - 1].size === currentSize) {
        const top = runningStack.pop();
        current = crypto.createHash('sha256').update(top.hash + current).digest('hex');
        currentSize *= 2;
      }
      runningStack.push({ size: currentSize, hash: current });

      const count = i + 1;
      const anchoredAtThisBlock = anchorsByBlockCount.get(count);
      if (anchoredAtThisBlock) {
        const computedRoot = this._computeRootFromStack(runningStack);
        for (const { anchor, aIdx } of anchoredAtThisBlock) {
          const expectedSig = crypto.createHmac('sha256', this.anchorSecret).update(anchor.merkleRoot).digest('hex');
          const sigBuf = Buffer.from(anchor.anchorSignature || '', 'hex');
          const expectedSigBuf = Buffer.from(expectedSig, 'hex');
          if (sigBuf.length !== expectedSigBuf.length || !crypto.timingSafeEqual(sigBuf, expectedSigBuf)) {
            verificationResults.isValid = false;
            verificationResults.merkleValid = false;
            verificationResults.errors.push(`Invalid anchor signature detected for anchor ${aIdx} at blockCount ${anchor.blockCount}`);
          }
          if (anchor.merkleRoot !== computedRoot) {
            verificationResults.isValid = false;
            verificationResults.merkleValid = false;
            verificationResults.errors.push(
              `Merkle root divergence at anchor ${aIdx} (blockCount ${anchor.blockCount}): expected ${anchor.merkleRoot.slice(0, 10)}..., found ${computedRoot.slice(0, 10)}...`
            );
          }
        }
      }
    }

    for (let aIdx = 0; aIdx < this.anchors.length; aIdx++) {
      const anchor = this.anchors[aIdx];
      if (this.chain.length < anchor.blockCount) {
        verificationResults.isValid = false;
        verificationResults.merkleValid = false;
        verificationResults.errors.push(
          `Audit chain truncation detected: chain length ${this.chain.length} is less than anchored blockCount ${anchor.blockCount}`
        );
      }
    }

    return verificationResults;
  }

  simulateTamper(index, field, newValue) {
    if (index < 0 || index >= this.chain.length) {
      throw new Error(`Invalid block index: ${index}`);
    }
    const originalValue = this.chain[index][field];
    this.chain[index][field] = newValue;
    this._rebuildMerkleStack();
    return {
      index,
      field,
      originalValue,
      tamperedValue: newValue
    };
  }
}

module.exports = WormAuditStore;
