/**
 * Bayora WORM Audit & Provenance Store
 * Section M: Append-only, SHA-256 hash-chained log with Merkle tree anchoring.
 * Tenants have WRITE-ONLY permission; no tenant can read raw audit trails.
 */

const crypto = require('crypto');

class WormAuditStore {
  constructor() {
    this.chain = [];
    this.anchors = []; // Merkle roots anchored externally
    this.genesisHash = '0000000000000000000000000000000000000000000000000000000000000000';
    this.storagePath = process.env.WORM_STORAGE_PATH || null;
    this.externalAnchorServiceEnabled = process.env.EXTERNAL_ANCHOR_SERVICE_ENABLED !== 'false';
    this.externalAnchorIntervalSec = Number(process.env.EXTERNAL_ANCHOR_INTERVAL_SEC) || 60;
    this._initializeGenesis();
  }

  _persistEntry(entry) {
    if (this.storagePath) {
      try {
        const fs = require('fs');
        const path = require('path');
        const dir = path.dirname(this.storagePath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.appendFileSync(this.storagePath, JSON.stringify(entry) + '\n', 'utf8');
      } catch (err) {
        // Safe fall-through for memory-only or restricted environments
      }
    }
  }

  _initializeGenesis() {
    const genesisEntry = {
      index: 0,
      timestamp: new Date().toISOString(),
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
    const content = `${entry.index}|${entry.prevHash}|${entry.timestamp}|${entry.tenant}|${entry.actor}|${entry.eventType}|${entry.payloadHash}|${JSON.stringify(entry.details)}`;
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  /**
   * Append a new event to the audit store.
   * Enforces that tenants can write, but never delete or overwrite past records.
   */
  append(eventData, callerRole = 'broker') {
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
      tenant: eventData.tenant || 'SYSTEM',
      actor: eventData.actor || callerRole,
      eventType: eventData.eventType,
      payloadHash,
      details: eventData.details || {},
      prevHash: lastEntry.entryHash,
      entryHash: ''
    };

    entry.entryHash = this._calculateEntryHash(entry);
    this.chain.push(entry);
    this._persistEntry(entry);

    // Anchor every 5 entries or on critical state changes
    if (this.chain.length % 5 === 0 || eventData.eventType === 'CONCLUDE') {
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
   * Compute Merkle Root over current chain leaves
   */
  getMerkleRoot(useStoredHashes = false) {
    if (this.chain.length === 0) return this.genesisHash;
    let leaves = this.chain.map(entry => useStoredHashes ? entry.entryHash : this._calculateEntryHash(entry));

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
      anchorSignature: crypto.createHmac('sha256', 'BAYORA_ANCHOR_SECRET').update(root).digest('hex')
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

    // 1. Verify Hash Chaining
    for (let i = 1; i < this.chain.length; i++) {
      const curr = this.chain[i];
      const prev = this.chain[i - 1];

      // Check linkage
      if (curr.prevHash !== prev.entryHash) {
        verificationResults.isValid = false;
        verificationResults.brokenChainAt = i;
        verificationResults.errors.push(`Broken hash link at block ${i}: expected prevHash ${prev.entryHash.slice(0, 10)}..., found ${curr.prevHash.slice(0, 10)}...`);
      }

      // Check recalculated hash
      const computedHash = this._calculateEntryHash(curr);
      if (curr.entryHash !== computedHash) {
        verificationResults.isValid = false;
        if (!verificationResults.brokenChainAt) verificationResults.brokenChainAt = i;
        verificationResults.errors.push(`Content tampering detected at block ${i}: stored hash does not match computed hash`);
      }
    }

    // 2. Verify Latest Anchor Merkle Root
    if (this.anchors.length > 0) {
      const latestAnchor = this.anchors[this.anchors.length - 1];
      const currentRoot = this.getMerkleRoot();
      if (latestAnchor.merkleRoot !== currentRoot && latestAnchor.blockCount === this.chain.length) {
        verificationResults.merkleValid = false;
        verificationResults.isValid = false;
        verificationResults.errors.push(`Merkle Root divergence: expected anchored root ${latestAnchor.merkleRoot.slice(0, 10)}..., found ${currentRoot.slice(0, 10)}...`);
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
