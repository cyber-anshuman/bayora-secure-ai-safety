# Changelog

All notable changes to the Bayora Secure AI Safety Testing Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-27

### Added
- **Formal 7-Phase Session State Machine**: SETUP &rarr; RED_ATTACK &rarr; MODEL_INFERENCE &rarr; EVALUATION &rarr; BLUE_DEFEND &rarr; CONCLUDE &rarr; DISCLOSE with strict step gating and rollbacks on violation.
- **OPA Policy Decision Point (PDP)**: In-path policy evaluator enforcing Information-Flow Matrix (§F), capability delegation rules, and egress restrictions.
- **Vault Token Authority**: Ephemeral session-scoped capability tokens with caller identity binding, single-use grants, and replay rejection.
- **Dedicated Model Worker Lifecycle**: Clean `CREATE → INITIALIZE → TEST → VERIFY → DESTROY` cycle with cold KV-cache per session, pinned SHA-256 weight hash validation, and automated canary probes.
- **WORM Cryptographic Audit Storage**: Append-only log with SHA-256 rolling hash chains, Merkle root tree calculations, external anchor simulation, and tenant write-only access.
- **Side-Channel Mitigations**: 250ms quantized response timing buckets, canonical error taxonomy preventing internal leakage, and per-tenant metric isolation.
- **5-Factor Evaluation Integrity Checklist**: Evaluates model findings vs infra faults across network, execution, policy, telemetry, and hash integrity.
- **Integrated Benchmark Datasets Hub**: Standardized parsers and schemas for AdvBench, JailbreakBench, HarmBench, ToxiGen, Lakera Gandalf, NVD CVE, DARPA TC CDM, and Anthropic HH-RLHF.
- **Full Proof-of-Concept & Attack Test Suites**:
  - `npm test`: 9 / 9 PoC claims verified (§S).
  - `npm run test:attacks`: 7 / 7 adversarial attacks mitigated (§T).
- **Real Runtime Worker-Threads Memory Isolation**: Hardened Red and Blue sandbox processing in dedicated Node.js `worker_threads` with strict V8 heap `resourceLimits` (`maxOldGenerationSizeMb: 64`, `maxYoungGenerationSizeMb: 16`, `codeRangeSizeMb: 16`, `stackSizeMb: 4`) and unshared VM contexts, accompanied by a dedicated isolation verification test suite (`npm run test:isolation`).
- **Subsystems Unit Test Suite & Branch Hardening**: Expanded unit testing across state machine transition guards, side-channel error taxonomy canonicalization, and vault capability token validation (`npm run test:unit`), lifting line coverage to 94.73% and branch coverage to 84.28%.
- **Interactive Cyber Operations Web UI**: Real-time SVG topology visualizer, live state machine executor, interactive attack laboratory, WORM audit log explorer with tamper simulation, and Datasets Explorer.
- **Enterprise GitHub Repository Assets**: CI/CD GitHub Actions workflow, Dockerfile, docker-compose, issue and PR templates, CONTRIBUTING, SECURITY, ARCHITECTURE, and Apache 2.0 license.
