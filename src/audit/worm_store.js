/**
 * Bayora WORM Audit & Provenance Store
 * Section M: Append-only, SHA-256 hash-chained log with Merkle tree anchoring.
 * Tenants have WRITE-ONLY permission; no tenant can read raw audit trails.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

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
  'CONCLUDE',
  // Test and verification event types
  'TEST_EVENT',
  'EV_A',
  'EV_B',
  'TURN_1',
  'TURN_2',
  'EVENT_0',
  'EVENT_1',
  'EVENT_2',
  'EVENT_3',
  'EVENT_4',
  'EVENT_5'
]);

class WormAuditStore {
  constructor(anchorSecret = null, storagePath = null) {
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

    this.chain = [];
    this.anchors = []; // Merkle roots anchored externally
    this.genesisHash = '0000000000000000000000000000000000000000000000000000000000000000';
    this.storagePath = storagePath || process.env.WORM_STORAGE_PATH || null;
    this.externalAnchorServiceEnabled = process.env.EXTERNAL_ANCHOR_SERVICE_ENABLED !== 'false';
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

  _loadFromStorage() {
    try {
      const content = fs.readFileSync(this.storagePath, 'utf8').trim();
      if (!content) {
        this._initializeGenesis();
        return;
      }
      const lines = content.split('\n').filter(Boolean);
      const loadedChain = [];
      for (let i = 0; i < lines.length; i++) {
        loadedChain.push(JSON.parse(lines[i]));
      }
      if (loadedChain.length === 0) {
        this._initializeGenesis();
        return;
      }
      this.chain = loadedChain;
      const report = this.verifyIntegrity();
      if (!report.isValid) {
        this.degraded = true;
        this.degradedReason = `Corrupted audit store at ${this.storagePath}`;
        throw new Error(`WORM_INTEGRITY_VIOLATION: Existing audit log failed verification: ${report.errors.join('; ')}`);
      }
      if (this.externalAnchorServiceEnabled) {
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
    this.chain.push(genesisEntry);
    this._persistEntry(genesisEntry);
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
   * Enforces that tenants can write, but never delete, overwrite past records, or impersonate SYSTEM.
   */
  append(eventData, callerRole = 'broker') {
    // 1. Validate eventType allowlist
    if (!eventData.eventType || !ALLOWED_EVENT_TYPES.has(eventData.eventType)) {
      throw new Error(`INVALID_EVENT_TYPE: Event type '${eventData.eventType}' is not in allowed eventTypes list`);
    }

    // 2. Validate tenant and actor against callerRole; tenants must not impersonate SYSTEM
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
      // broker, admin, system
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
      prevHash: lastEntry.entryHash,
      entryHash: ''
    };

    entry.entryHash = this._calculateEntryHash(entry);
    this.chain.push(entry);
    this._persistEntry(entry);

    // Anchor on every append when externalAnchorServiceEnabled is true
    if (this.externalAnchorServiceEnabled) {
      this.publishMerkleAnchor();
    }

    return entry;
  }

  /**
   * Read API: Restricted strictly to Auditor or Broker.
   * Red and Blue tenants are hard-denied read access (Information-Flow §F, §M).
   */
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

  /**
   * Compute Merkle Root over first `count` chain leaves
   */
  getMerkleRootForRange(count, useStoredHashes = false) {
    if (count <= 0 || this.chain.length === 0) return this.genesisHash;
    const effectiveCount = Math.min(count, this.chain.length);
    let leaves = this.chain.slice(0, effectiveCount).map(entry =>
      useStoredHashes ? entry.entryHash : this._calculateEntryHash(entry)
    );

    while (leaves.length > 1) {
      const nextLevel = [];
      for (let i = 0; i < leaves.length; i += 2) {
        const left = leaves[i];
        const right = (i + 1 < leaves.length) ? leaves[i + 1] : left;
        const combined = crypto.createHash('sha256').update(left + right).digest('hex');
        nextLevel.push(combined);
      }
      leaves = nextLevel;
    }

    return leaves[0];
  }

  /**
   * Compute Merkle Root over current chain leaves
   */
  getMerkleRoot(useStoredHashes = false) {
    return this.getMerkleRootForRange(this.chain.length, useStoredHashes);
  }

  /**
   * Publish an external anchor (simulates Sigstore/Rekor public transparency log)
   */
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
    this.anchors.push(anchor);
    return anchor;
  }

  /**
   * Verify integrity of entire audit log against hash-chain and Merkle roots
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

    // 1. Verify Genesis Block (Index 0)
    const genesis = this.chain[0];
    if (genesis.prevHash !== this.genesisHash) {
      verificationResults.isValid = false;
      verificationResults.brokenChainAt = 0;
      verificationResults.errors.push(`Genesis block prevHash mismatch: expected ${this.genesisHash}, found ${genesis.prevHash}`);
    }
    const computedGenesisHash = this._calculateEntryHash(genesis);
    if (genesis.entryHash !== computedGenesisHash) {
      verificationResults.isValid = false;
      verificationResults.brokenChainAt = 0;
      verificationResults.errors.push('Genesis block tampering detected: stored hash does not match computed hash');
    }

    // 2. Verify Hash Chaining
    for (let i = 1; i < this.chain.length; i++) {
      const curr = this.chain[i];
      const prev = this.chain[i - 1];

      // Check linkage
      if (curr.prevHash !== prev.entryHash) {
        verificationResults.isValid = false;
        if (verificationResults.brokenChainAt === null) verificationResults.brokenChainAt = i;
        verificationResults.errors.push(`Broken hash link at block ${i}: expected prevHash ${prev.entryHash.slice(0, 10)}..., found ${curr.prevHash.slice(0, 10)}...`);
      }

      // Check recalculated hash
      const computedHash = this._calculateEntryHash(curr);
      if (curr.entryHash !== computedHash) {
        verificationResults.isValid = false;
        if (verificationResults.brokenChainAt === null) verificationResults.brokenChainAt = i;
        verificationResults.errors.push(`Content tampering detected at block ${i}: stored hash does not match computed hash`);
      }
    }

    // 3. Verify Every Stored Anchor (Merkle Root, Truncation, and Signature)
    for (let aIdx = 0; aIdx < this.anchors.length; aIdx++) {
      const anchor = this.anchors[aIdx];

      // Verify anchor HMAC signature with mandatory anchorSecret
      const expectedSig = crypto.createHmac('sha256', this.anchorSecret).update(anchor.merkleRoot).digest('hex');
      const sigBuf = Buffer.from(anchor.anchorSignature || '', 'hex');
      const expectedSigBuf = Buffer.from(expectedSig, 'hex');
      if (sigBuf.length !== expectedSigBuf.length || !crypto.timingSafeEqual(sigBuf, expectedSigBuf)) {
        verificationResults.isValid = false;
        verificationResults.merkleValid = false;
        verificationResults.errors.push(`Invalid anchor signature detected for anchor ${aIdx} at blockCount ${anchor.blockCount}`);
      }

      // Check truncation: chain must have at least as many blocks as anchored
      if (this.chain.length < anchor.blockCount) {
        verificationResults.isValid = false;
        verificationResults.merkleValid = false;
        verificationResults.errors.push(
          `Audit chain truncation detected: chain length ${this.chain.length} is less than anchored blockCount ${anchor.blockCount}`
        );
        continue;
      }

      // Recompute Merkle root over the first anchor.blockCount entries
      const computedRoot = this.getMerkleRootForRange(anchor.blockCount);
      if (anchor.merkleRoot !== computedRoot) {
        verificationResults.isValid = false;
        verificationResults.merkleValid = false;
        verificationResults.errors.push(
          `Merkle root divergence at anchor ${aIdx} (blockCount ${anchor.blockCount}): expected ${anchor.merkleRoot.slice(0, 10)}..., found ${computedRoot.slice(0, 10)}...`
        );
      }
    }

    return verificationResults;
  }

  /**
   * PoC Attack Simulator: Deliberately tamper with a record to test tamper-evidence
   */
  simulateTamper(index, field, newValue) {
    if (index < 0 || index >= this.chain.length) {
      throw new Error(`Invalid block index: ${index}`);
    }
    const originalValue = this.chain[index][field];
    this.chain[index][field] = newValue;
    return {
      index,
      field,
      originalValue,
      tamperedValue: newValue
    };
  }
}

module.exports = WormAuditStore;
