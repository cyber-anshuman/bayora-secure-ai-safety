# Changelog

All notable changes to the Bayora Secure AI Safety Testing Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-27

### Added
- **Session State Machine**: `SETUP -> RED_TURN -> MODEL_INFERENCE -> EVAL -> BLUE_TURN -> CONCLUDE -> DISCLOSURE` with strict fail-closed step gating.
- **OPA Policy Decision Point (PDP)**: In-path default-deny policy evaluator enforcing Information-Flow Matrix (§F), capability delegation rules, and egress restrictions.
- **Vault Token Authority**: Ephemeral session-scoped capability tokens with caller identity binding, single-use action consumption, cryptographic lease tracking, and replay rejection.
- **Dedicated Model Worker Lifecycle**: Clean `CREATE → INITIALIZE → TEST → VERIFY → DESTROY` cycle with cold KV-cache per session, pinned weight hash verification (or UNPINNED_DEMO_MODEL reporting), and automated canary probes.
- **WORM Cryptographic Audit Storage**: Append-only log with SHA-256 rolling hash chains, Merkle root tree calculations, external HMAC-signed anchor verification, and tenant write-only access.
- **Side-Channel Mitigations**: 250ms quantized response timing buckets, monotonic clock delay quantization, canonical error taxonomy preventing internal leakage, and per-tenant metric isolation.
- **5-Factor Evaluation Integrity Checklist**: Evaluates model findings vs infra faults across canary, hash integrity, clean infra, resource metrics, and audit ledger reconstructability.
- **Integrated Benchmark Datasets Hub**: Standardized parsers and schemas for AdvBench, JailbreakBench, HarmBench, ToxiGen, Lakera Gandalf, NVD CVE, DARPA TC CDM, and Anthropic HH-RLHF.
- **Full Proof-of-Concept & Attack Test Suites**:
  - `npm test`: Runs full test suite covering all 9 PoC claims (§S), 7 adversarial attack simulations (§T), unit tests, isolation tests, and HTTP integration suite.
- **Runtime Worker-Threads Memory Isolation**: Hardened Red and Blue sandbox processing in dedicated Node.js `worker_threads` with strict V8 heap `resourceLimits` (`maxOldGenerationSizeMb: 64`, `maxYoungGenerationSizeMb: 16`, `codeRangeSizeMb: 16`, `stackSizeMb: 4`) and unshared memory heaps, bounded by a concurrency semaphore.
- **Enterprise GitHub Repository Assets**: CI/CD GitHub Actions workflow, multi-stage Dockerfile, docker-compose with read-only rootfs, and Apache 2.0 license.
