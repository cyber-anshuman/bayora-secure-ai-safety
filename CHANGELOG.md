# Changelog

All notable changes to the Bayora Secure AI Safety Testing Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-10-20

### Security & Robustness Fixes (Round 1 & Round 2 Audits)
- **Interactive Dashboard Repair**:
  - Added in-memory API key management panel for Admin, Red, Blue, and Auditor keys without insecure `localStorage` persistence.
  - Implemented centralized `api()` fetch helper setting `X-API-Key` headers and handling 401/403/404 responses gracefully.
  - Reconstructed end-to-end multi-turn evaluation lifecycle: setup (`POST /api/sessions`), token acquisition (`/token`), red submission (`ACCEPTED`), model output inspection (`/model-output`), blue defense turn, coarse status polling (`/coarse-status`), and certified disclosure (`/disclosure`).
  - Added graceful degradation messaging ("Demo endpoints are disabled on this server") when demo endpoints are gated.
- **Capability Token Lifecycle Hardening**:
  - Reordered `getDisclosureBundle` to evaluate capability validation and OPA phase checks before consuming the `read_disclosure` token, ensuring premature disclosure attempts during `RED_TURN` do not permanently burn the token.
  - Implemented atomic capability action consumption and phase transition with zero asynchronous tick window, preventing concurrent submission race conditions.
  - Issued dedicated `read_red_payload` capability token to decouple post-conclude red payload queries from disclosure bundle retrieval.
- **Audit Store Hygiene & DoS Prevention**:
  - Enforced token and state phase checks in sandbox handlers before any audit append or worker dispatch, ensuring wrong-phase calls write 0 audit entries.
  - Added headroom reservation for active sessions to conclude even when approaching `MAX_AUDIT_ENTRIES`.
- **WORM Audit Engine Scaling ($O(\log n)$ Append & $O(n)$ Verify)**:
  - Replaced $O(n^2)$ full-chain recalculation with incremental Merkle Mountain Range/stack caching.
  - Bound periodic anchor publishing to every 10 appends (`ANCHOR_EVERY_N = 10`) and session `CONCLUDE`.
  - Added single-pass $O(n)$ `verifyIntegrity()`, `verifyTail(fromIndex)` for model inference hot paths, and non-blocking chunked `verifyIntegrityAsync()` for API verification.
  - Implemented persistent anchor storage in sibling `.anchors.jsonl` verified on startup against tampering and truncation.
  - Added pagination (`limit`, `offset`) and metadata (`latestAnchor`, `anchorCount`) to `/api/audit`.
- **Container Deployment & Production Secret Validation**:
  - Added non-root `/data` directory initialization and ownership assignment in `Dockerfile` before declaring `VOLUME ["/data"]`.
  - Pinned base container image to verified Alpine digest `node:20.18.0-alpine@sha256:b1e0880c3af955867bc2f1944b49d20187beb7afa3f30173e15a97149ab7f5f1`.
  - Made `.env` file optional in `docker-compose.yml`.
  - Stripped default placeholder secrets in `.env.example` and added startup check refusing known-example secrets when `NODE_ENV=production`.
- **Security Gap Remediation**:
  - Mandated capability token validation and consumption for `GET /api/sessions/:id/coarse-status`.
  - Removed insecure URL query token support (`req.query.token`), restricting capability tokens strictly to `Authorization: Bearer` or `X-Capability-Token` headers.
  - Unified tenant endpoint check ordering (egress -> existence -> capability token -> phase) to return canonical 403 `SEC_ERR_01` errors, closing phase oracle side channels.
  - Cryptographically bound `initialIssuedAt` into capability token signatures and server-side tracking, preventing lifetime cap resets.
  - Canonicalized `/disclosure` and `/red-payload-query` authentication errors to standard 403.
- **Honest Evaluation Integrity & Positive Controls**:
  - Computed observed configuration and dataset hashes dynamically from runtime session parameters rather than comparing against self-referenced expected objects.
  - Capped unpinned demo models at `UNVERIFIED` with `downgradeReason: 'weights not pinned (demo model)'`.
  - Added `ALLOW_UNPINNED_DEMO` policy gating, refusing unpinned models in production.
  - Replaced arbitrary CPU modulo calculations with genuine per-session worker CPU sampling over elapsed wall time.
  - Added positive controls for timing side-channels (Sim 2: unquantized distinguishable vs quantized indistinguishable) and KV-cache leakage (Sim 3: shared cache probe caught vs isolated cold cache protected).
  - Explicitly disclosed canary probe limitations in code documentation and README.
- **Hygiene & Strict Linting**:
  - Cleaned all ESLint unused variable/parameter warnings across codebase and enforced `--max-warnings 0`.
  - Added automated contract test verifying all endpoints documented in `README.md` are defined in `src/server.js`.

## [1.0.0] - 2026-09-27

### Added
- **Session State Machine**: `SETUP -> RED_TURN -> MODEL_INFERENCE -> BLUE_TURN -> CONCLUDE -> DISCLOSURE` with strict fail-closed step gating.
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
