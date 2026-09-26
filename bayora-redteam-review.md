# Bayora — Adversarial Review & Redesign of the Secure AI Safety Testing Architecture

---

## A. Executive Summary

The fundamental problem in Bayora is **not** "how do we containerize three services." It is:

> How do you run three *mutually distrusting, actively adversarial* parties — an attacker, a defender, and a subject-under-test — concurrently, on shared infrastructure, such that none of them can learn anything about the others except through an explicitly authorized, policy-controlled channel, **and** you can later prove to a third party that the recorded outcome actually happened as described?

This is harder than standard multi-tenancy because:
1. The tenants are *incentivized* to break isolation (red vs blue team leaking = one side wins for free).
2. The "workload under test" (the LLM) is not a passive resource like a database — it can behave adaptively, encode information in its outputs, and be influenced by its execution environment (batching, cache) in ways that create *new* channels ordinary infra security doesn't consider.
3. "Isolation" and "evaluation validity" are in tension: aggressive isolation (VM-level, no shared cache, padded timing) can add latency/noise that itself invalidates the very finding you're trying to certify.

The original proposal (mandatory-mediation broker + gVisor/Kata + Cilium + OPA/Vault + hash-chained audit log) is a reasonable **skeleton**. It is not a security architecture yet — it is a list of good tools without a threat model, without an information-flow analysis, and without any accounting for LLM-specific and side-channel leakage. This document tears it down and rebuilds it.

---

## B. Original Solution — What It Got Right

Purely factual strengths, no editorializing:

- **Mandatory mediation** (no direct red↔blue, red↔model, blue↔model paths) is structurally correct and is retained in the revised design — it collapses "N-party isolation" into "N one-to-one boundaries with a trusted broker," which is the right reduction.
- Choosing **gVisor/Kata over bare containers** for the highest-risk tenant (red team) correctly recognizes that a Linux container is not a security boundary by default.
- **Vault + OPA** for secrets/policy is a legitimate least-privilege pattern and avoids static, long-lived credentials.
- **Hash-chained append-only audit log** is the right primitive for tamper-evidence.
- Explicit **session state machine** (`SETUP → RED_TURN → MODEL_INFERENCE → EVAL → BLUE_TURN → CONCLUDE → DISCLOSURE`) correctly encodes "blue team cannot see before conclusion" as an enforced state rather than a policy the components are trusted to follow.
- It correctly flagged (even if only briefly) KV-cache sharing, timing side channels, and a compromised-broker single point of trust as residual risks — most submissions won't even mention these.

Everything else below is either missing, underspecified, or wrong.

---

## C. Critical Weaknesses

1. **No formal information-flow analysis.** The design blocks *direct* channels but never enumerates metadata, timing, resource, and LLM-native channels — which is exactly where a determined red/blue team will look first, because direct channels are the obvious ones to defend.
2. **The broker is a god-object and a single point of both trust and failure**, and the original solution only names this in passing. A compromised or buggy broker sees *everything* — it is the one place where cross-tenant leakage would be catastrophic and totally silent.
3. **"Isolate compute" was conflated with "isolate information."** gVisor/Kata stop *syscall-level* escape, but say nothing about what the model's own inference stack (batching, prefix cache, logging, metrics) leaks *through legitimate, policy-permitted channels* (e.g., the model's response itself, or aggregate telemetry both teams can see).
4. **No definition of "clean model."** Nowhere does the original design specify what state must be destroyed between tests (KV-cache, adapter/LoRA state, retrieval DB, tool state, logs) or how you'd *prove* a prior red-team turn didn't leak into a later blue-team-observed baseline. This is a named requirement in the problem statement and the original solution never operationalizes it.
5. **No evaluation-integrity mechanism.** There's no way, in the original design, to distinguish "the model failed the safety test" from "the sandbox network hiccupped and produced a truncated response that looks like a jailbreak succeeded." Given the objective explicitly says findings must not be invalidated by environmental leakage, this is a direct gap against a stated requirement, not a nice-to-have.
6. **Observability was an afterthought.** A SIEM/Falco layer that is merely "read-only to tenants" still typically exposes *aggregate* dashboards, shared alert channels, or shared ticketing — any of which can leak (e.g., "an alert fired" is itself a bit of information).
7. **No concurrency/race-condition analysis**, despite "simultaneously" being explicitly called out as a requirement in the problem statement. Broker state-machine transitions, cache eviction, and log writes under concurrent load were not modeled.
8. **No supply-chain or cloud-specific analysis** — base images, model weights, and dataset provenance are unaddressed; IMDS/metadata-service exposure (a classic container-escape payoff) is not discussed at all.
9. **Latency-padding was proposed as a timing-channel mitigation but then contradicted** by the objective "avoid latency that invalidates evaluation results" — the original solution names this tension but doesn't resolve it.
10. **Residual-risk section lacks structure/rigor** — "protects against / doesn't protect against" is a start, but there's no per-threat table, no preconditions, no way to actually test the claims (Rule: every claim needs a test — the original solution has zero).

---

## D. Threat Model

### Assets
| Asset | Sensitivity | Held by |
|---|---|---|
| Red-team attack payloads (pre-conclusion) | High | Red sandbox, broker (in transit) |
| Blue-team defensive logic / classifier weights / thresholds | High | Blue sandbox, Vault |
| Client LLM weights & serving config | High | Model sandbox |
| Model KV-cache / inference session state | High (transient) | Inference runtime |
| Evaluation findings (pre-disclosure) | High | Broker, audit store |
| Audit log | Integrity-critical | Audit service |
| Dataset (AdvBench/JailbreakBench/etc.) | Medium | Dataset store |
| Cloud credentials / service identities | Critical | IAM, Vault |
| Telemetry/metrics/logs | Medium (can encode High) | Observability stack |

### Attackers

**A. Malicious Red Team** — goal: learn blue-team detection logic/thresholds to craft payloads that evade it, or learn about other tenants/infra to pivot. Capability: full control of red-sandbox code, arbitrary requests to broker, can shape payload content/timing/size to probe side channels.

**B. Malicious Blue Team** — goal: learn upcoming red payloads/strategy to "win" without genuinely improving defenses, or learn about hidden test cases to game the benchmark. Capability: full control of blue-sandbox code, can shape defensive-logic timing/behavior to probe.

**C. Compromised/Adversarial Client LLM** — goal (from the model's "perspective" as an adversarial test subject, or a fine-tuned/backdoored model): exfiltrate information via output encoding (e.g., steering token distribution to leak bits through response length/formatting), infer hidden system prompts, exploit any tool-call surface, exploit shared serving infra (cache-based cross-session leakage). This is not paranoia — it is literally what "jailbreak" testing tries to elicit, so the infrastructure must assume the model **will** attempt this.

**D. Compromised Container** — arbitrary code execution inside any one workload (red, blue, or model). Must be assumed to attempt: container escape, kernel exploitation, `/proc` and `/sys` inspection, shared-volume/socket abuse, IMDS access, lateral movement to the broker or audit store.

**E. Malicious Insider / Operator** — has legitimate administrative access (cluster admin, cloud console, Vault root). Can, in the original design, silently read Vault secrets, modify Kubernetes network policy, or edit audit-store data unless WORM/immutable storage and split-key admin are in place.

**F. External Attacker** — targets the Bayora control plane (ingress, orchestrator API, CI/CD, container registry) from outside, seeking initial foothold, typically via the weakest exposed surface: the orchestrator's public API or a poisoned dependency.

### Trust classification
- **Untrusted, actively adversarial, always:** Red team, Blue team, Client LLM outputs.
- **Trusted but must be constrained (least privilege, auditable):** Broker/orchestrator, OPA policy engine, Vault.
- **Trusted root of integrity (must be protected above all):** Audit/provenance log signing key, admin break-glass procedures.
- **Assumed hostile environment:** the underlying cloud/host — i.e., do not assume the hypervisor/host is uncompromised; degrade gracefully, don't rely on it as the *only* boundary.

---

## E. Trust Boundaries

```
 ┌─────────────────────────────────────────────────────────────────────┐
 │                          CLOUD / HOST (untrusted-by-default)          │
 │  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌─────────────────┐ │
 │  │ RED VM/mVM│   │ BLUE VM/mVM│  │ MODEL VM  │   │ AUDIT (WORM)    │ │
 │  │ (Kata)    │   │ (Kata)     │  │ (Kata/GPU)│   │ append-only     │ │
 │  └─────┬─────┘   └─────┬─────┘   └─────┬─────┘   └────────┬────────┘ │
 │        │  mTLS         │ mTLS          │ mTLS             │ sign-only│
 │        └──────────────►│◄──────────────┘                  │          │
 │                 ┌───────────────┐                          │         │
 │                 │  BROKER /     │──────────────────────────┘         │
 │                 │  ORCHESTRATOR │  (only entity that talks to >1)    │
 │                 │  + OPA PDP    │                                    │
 │                 └───────┬───────┘                                    │
 │                         │                                            │
 │                 ┌───────▼───────┐                                    │
 │                 │ VAULT (secrets)│                                   │
 │                 └───────────────┘                                    │
 └─────────────────────────────────────────────────────────────────────┘
```

Boundaries and what crosses them:

1. **Red sandbox ↔ Broker** — only: signed attack-turn submissions, session-state queries. Never: blue defensive logic, model internals.
2. **Blue sandbox ↔ Broker** — only: defensive-logic updates, post-`CONCLUDE` disclosure payloads. Never: red payload content before `CONCLUDE`.
3. **Model sandbox ↔ Broker** — only: inference request/response for the current session, scoped to that session's fresh context. Never: cross-session context, other tenants' identifiers.
4. **All sandboxes ↔ Vault** — only their own scoped, short-lived lease. Never each other's secret paths (enforced by Vault policy, not by convention).
5. **All sandboxes ↔ Audit store** — **write-only, append-only**, one-way. No sandbox can *read* the audit log (this closes a leakage path the original design left implicit).
6. **Broker ↔ Audit store** — read/write, but write path is hash-chained and the broker cannot rewrite prior entries (enforced by the storage layer, not the broker's good behavior).
7. **Host/Cloud ↔ everything** — assumed capable of observing resource usage; mitigated by cgroup quotas and (where available) confidential computing, never assumed impossible.
8. **Administrator ↔ everything** — break-glass only, dual-control, logged to a *separate* immutable channel that even the administrator cannot edit post-hoc.

---

## F. Information-Flow Matrix

| Source | Destination | Allowed Data | Forbidden Data | Enforcement |
|---|---|---|---|---|
| Red sandbox | Broker | Payload text, session ID, turn metadata (size class, not exact size — see §G) | Nothing about blue defenses | mTLS + OPA policy on message schema |
| Broker | Model sandbox | Current-turn prompt only, fresh session context | Any prior session's context, other tenant IDs | Broker enforces fresh-context injection every turn |
| Model sandbox | Broker | Raw output for current session | KV-cache handle, internal token probabilities beyond what's needed | Output filtered to declared schema only |
| Broker | Blue sandbox | Only post-`CONCLUDE` disclosure bundle (full/redacted per policy) | Red payload during `RED_TURN`/`MODEL_INFERENCE` | State-machine gate, hard-denied by OPA, not just "not sent yet" |
| Blue sandbox | Broker | Defensive verdict/classification result | Internal model weights, thresholds, training data | Schema-limited response |
| Broker | Red sandbox | Only aggregate pass/fail after `CONCLUDE`, no defensive rationale | Blue detection logic, confidence scores, internal features | Schema-limited + redaction policy |
| Any sandbox | Audit store | Hash of artifact + metadata | — (this is a write sink, nothing flows back) | One-way write API, no read scope granted |
| Observability stack | Any tenant dashboard | Own-tenant resource metrics only, quantized/bucketed | Other tenant's exact CPU/mem/latency values, alert content referencing other tenant | Per-tenant metric namespace + bucketing (see §N) |
| Broker | Everyone | Session phase (public: e.g. "in progress") | Any content-bearing signal disguised as status | Status enum kept coarse and identical shape regardless of what's happening |

Metadata columns worth calling out explicitly because the original design ignored them: **timestamps** (coarsen to avoid inferring processing duration precisely), **request IDs** (must be unlinkable across tenants — use per-tenant-scoped IDs, not a global monotonic counter that leaks ordering/volume), **error messages** (must be genericized — "request failed" not "blue classifier threw NullPointerException on line 42"), **HTTP status codes** (collapse to a small set; don't let 429 vs 500 vs 403 leak *why*), **retries** (don't expose retry count to the other tenant — it can leak "the model struggled with this input").

---

## G. Side-Channel Analysis

For each channel: mechanism → attacker capability needed → info leaked → severity → exploitability → mitigation → residual risk.

### 1. Timing channel (response latency)
- **Mechanism:** Blue team observes total wall-clock time from submitting a defense-relevant config change to the next disclosure; or infers from *aggregate* system latency whether red team is currently running an expensive/long attack (e.g., a long chain-of-thought jailbreak vs. a one-liner).
- **Capability:** Ability to send its own timed requests to the broker and observe response time, even with zero visibility into red content.
- **Leak:** Coarse signal about red payload complexity/length/strategy category.
- **Severity:** Medium. **Exploitability:** Practical — timing side channels are cheap to probe repeatedly.
- **Mitigation:** Quantized response-time buckets (e.g., round up to nearest 250ms) for any cross-tenant-visible timing; dedicated non-shared inference workers per session so one tenant's load never changes another's queueing delay; publish only session-phase transitions, not durations, to the other tenant.
- **Residual risk:** Bucketing reduces resolution but doesn't eliminate a patient, repeated-sampling adversary. Full elimination requires constant-time response scheduling, which trades against the "don't invalidate evaluation with latency" objective — this is a genuine, stated trade-off, not a solved problem.

### 2. Resource-contention channel (CPU/mem/GPU)
- **Mechanism:** If red and blue share a node/scheduler, blue's own measured throughput dips when red is running a heavy workload — a covert channel with attacker-controlled bandwidth (red can encode bits by choosing to run CPU-heavy vs idle turns).
- **Mitigation:** Disjoint cgroup `cpuset`s and, ideally, disjoint physical nodes/NUMA domains for red vs blue vs model; disable SMT co-scheduling across tenants; enforce hard, equal quotas so contention cannot leak variable signal.
- **Residual risk:** Cross-node scheduler-level signals (e.g., cluster autoscaling events visible to both) can still leak coarse load info unless the orchestration layer itself is tenant-blind.

### 3. Shared-filesystem / cache channel
- **Mechanism:** Any shared volume, shared `/tmp`, or shared container-layer cache lets one tenant infer the other's activity via file existence, mtimes, or disk-cache warm/cold timing (classic cross-VM cache attack pattern, e.g. Flush+Reload-style at the filesystem layer).
- **Mitigation:** No shared volumes, ever, between tenants — enforced structurally (separate PVs, separate storage classes), not by convention. Per-session ephemeral rootfs, destroyed after each turn.
- **Residual risk:** Underlying storage backend (e.g., a shared network filesystem or object store bucket) can still leak via access-pattern telemetry if not partitioned per tenant with separate credentials.

### 4. Network-level channels (DNS, connection success/failure, metadata)
- **Mechanism:** If red can attempt (even blocked) connections and observe *which* attempts are denied vs. accepted, it can map internal service topology; DNS queries to internal names can leak service existence.
- **Mitigation:** Default-deny egress with **uniform** failure behavior (all denied connections look identical — connection refused, not "host unreachable" vs "filtered", which differ informatively); internal DNS split so red/blue resolve only their own broker endpoint; block cloud metadata endpoint (`169.254.169.254`) entirely from tenant sandboxes at the network-namespace level, not just via IAM.
- **Residual risk:** Low if uniformly enforced; moderate if policy is inconsistent across environments (a classic operational drift risk).

### 5. Process/`/proc`/`/sys` channel
- **Mechanism:** Under shared PID namespace or host-visible `/proc`, one tenant enumerates process names/args of another (e.g., seeing a `blue-classifier --threshold=0.83` argv).
- **Mitigation:** Separate PID namespaces per tenant (already implied by Kata's VM boundary — call this out explicitly as *why* Kata > plain containers here); never pass secrets via argv/env visible in `/proc`; secrets injected via short-lived file mounts from Vault with tmpfs, not env vars.
- **Residual risk:** Near-zero with true VM isolation; **high** if the original "gVisor for red only" plan is kept, because gVisor still shares the host kernel more than a real VM boundary would for the *other* tenants if they're left on plain containers — inconsistent hardening is itself a vulnerability.

### 6. LLM-native channel: KV-cache / prefix-cache sharing
- **Mechanism:** Serving stacks like vLLM/TGI share KV-cache across concurrent requests for efficiency (prefix caching). If red and blue-observed baseline sessions share a serving pool with prefix caching enabled, timing of *cache hits* (faster response = prefix was already computed, meaning someone else sent a similar/identical prefix) leaks information about what's been run before.
- **Capability:** Ability to submit crafted prefixes and measure response latency.
- **Severity:** High — this is the most Bayora-specific, least "generic infra" channel, and is exactly the kind of thing judges will want to see addressed concretely.
- **Mitigation:** Disable cross-session prefix caching entirely, or partition cache pools per session with mandatory flush between turns; if throughput requires caching, cache only *within* a single tenant's own session, never across the red/blue boundary.
- **Residual risk:** Performance cost is real (cache-disabled serving is slower); this is the direct example of the "isolation vs. evaluation validity" tension called out in the objectives — must be an explicit, documented trade-off, not silently dropped.

### 7. LLM-native channel: output encoding / steganographic exfiltration
- **Mechanism:** A model under adversarial pressure (or backdoored) could encode information into subtle output features — token choice, whitespace, response length — to exfiltrate context to whichever party reads the output.
- **Mitigation:** Output schema normalization/canonicalization before forwarding through the broker (strip/normalize whitespace, cap length, potentially paraphrase-and-hash rather than pass raw text where feasible); this is a genuinely hard, open problem — state it as **partially mitigated, not solved**.

### 8. Application-layer channels (error messages, token counts, response length)
- **Mechanism:** Raw error stack traces, token counts, or exact response byte-length passed through the broker can leak implementation details of the other tenant (e.g., blue's classifier crashing on certain inputs reveals its fragility).
- **Mitigation:** Canonical error taxonomy (a fixed, small enum of error classes) returned to the *other* tenant regardless of true internal cause; token counts bucketed, not exact, when cross-tenant-visible.

---

## H. Container/Runtime Security

**Critical correction to the original design:** it applied strong isolation (gVisor/Kata) only conceptually and didn't specify it uniformly. **Every** tenant workload — red, blue, *and* model — must get the same tier of isolation; asymmetric hardening just moves the weakest link.

- **Runtime:** Kata Containers (VM-boundary, hardware-virtualized) for all three tenant workloads. gVisor is an acceptable fallback where nested virtualization isn't available (e.g., some cloud CI runners), but document that this is a materially weaker boundary (syscall interception vs. real VM) and reflect that in the residual-risk table.
- **What each control actually provides, and its limit:**
  - *User namespaces:* remaps root-in-container to unprivileged host UID — prevents trivial host-root-via-container-root, does **not** prevent kernel exploitation.
  - *seccomp-bpf:* blocks unneeded syscalls (ptrace, mount, unshare, etc. for tenant workloads) — reduces kernel attack surface, does **not** stop attacks using only allow-listed syscalls.
  - *Read-only rootfs + no bind mounts:* prevents persistence and shared-volume side channels — does **not** stop in-memory attacks or network exfiltration.
  - *Dropped capabilities (`--cap-drop=ALL`, add back only what's needed):* prevents e.g. `CAP_NET_RAW` sniffing — does **not** stop application-layer logic bugs.
  - *Kata's VM boundary:* the actual hard boundary against kernel-level container escape — its limit is that it still shares the *hypervisor and physical host*, so hardware side-channels (cache timing, Spectre-class) are **not** addressed by Kata alone.
- **What if red gets arbitrary code execution inside its sandbox (assume it happens):**
  - Container escape to host: blocked by Kata's VM boundary in the common case; **not** blocked against a hypervisor 0-day (name this explicitly as out-of-scope-but-acknowledged).
  - Access to Docker socket / runtime API: eliminated by not mounting the socket into any tenant workload — verify this in the PoC with an explicit negative test.
  - Cloud metadata access: blocked by network-namespace egress rule denying `169.254.169.254`, enforced redundantly at the CNI layer, not just IAM.
  - Lateral movement to broker: blocked by mTLS with per-session short-lived client certs — an attacker inside red sandbox has red's cert only, scoped by OPA to red's allowed actions.
  - Inspecting other namespaces: blocked structurally — Kata gives each tenant its own kernel, not just namespace-separated views of one kernel.

---

## I. Network Security

| Connection | Verdict | Rationale |
|---|---|---|
| RED → BROKER | ALLOW (mTLS, schema-limited) | Only sanctioned path for red submissions |
| RED → BLUE | DENY | No legitimate reason ever |
| RED → MODEL | DENY (direct) | Must go through broker for mediation/logging |
| RED → AUDIT | ALLOW, write-only | One-way evidence submission |
| BLUE → BROKER | ALLOW (mTLS, schema-limited) | Only sanctioned path |
| BLUE → RED | DENY | No legitimate reason ever |
| BLUE → MODEL | DENY (direct) | Same as red |
| BLUE → AUDIT | ALLOW, write-only | Same as red |
| MODEL → BROKER | ALLOW (mTLS, response only) | Model never initiates unsolicited connections |
| MODEL → RED / MODEL → BLUE | DENY | Model must never learn who is testing it |
| MODEL → EXTERNAL (internet) | DENY (egress) | Prevents model-driven exfiltration entirely — a genuinely adversarial LLM should have **zero** general internet egress |
| BROKER → RED / BLUE / MODEL | CONDITIONAL, gated by session-state machine | Only the state machine's currently-permitted edges are open; enforced by OPA at every hop, re-evaluated per request (not cached as "session started, all good") |
| BROKER → AUDIT | ALLOW, append-only API | No delete/update verbs exposed at all, not just access-denied — remove the capability, don't just gate it |
| ANY TENANT → CLOUD METADATA | DENY, defense-in-depth (network + IAM + seccomp) | Classic post-escape pivot point; block at every layer independently |
| ANY TENANT → ANY TENANT | DENY, default | Zero-trust default-deny CNI policy (Cilium), explicit allow-list only for the edges above |

Enforcement stack: Cilium (eBPF) default-deny `CiliumNetworkPolicy` per namespace + mTLS via SPIFFE/SPIRE identities (stronger than plain cert rotation — gives cryptographic workload identity independent of IP, which matters because pods get rescheduled) + OPA as the policy decision point sitting in the broker's request path, re-checked on every call, not just at session setup.

---

## J. Access Control (Capability Table)

| Principal | Resource | Read | Write | Execute | Delete | Share | Required? |
|---|---|---:|---:|---:|---:|---:|---:|
| Red sandbox | Own payload workspace | Y | Y | Y | Y (own only) | N | Yes |
| Red sandbox | Blue defensive-logic store | N | N | N | N | N | No |
| Red sandbox | Model weights | N | N | N | N | N | No |
| Red sandbox | Audit store | N | Y (append) | N | N | N | Yes (evidence) |
| Blue sandbox | Own defensive-logic store | Y | Y | Y | Y (own only) | N | Yes |
| Blue sandbox | Red payload store | N (pre-conclusion) / partial (post, per disclosure policy) | N | N | N | N | Conditional |
| Blue sandbox | Model weights | N | N | N | N | N | No |
| Model sandbox | Own weights (local mount) | Y | N | Y | N | N | Yes |
| Model sandbox | Red/blue stores | N | N | N | N | N | No |
| Broker | All session metadata | Y | Y | N | N (append-only downstream) | N | Yes |
| Broker | Vault (per-tenant secret paths) | Y (scoped lease) | N | N | N | N | Yes |
| Broker | Audit store | Y | Y (append) | N | N | N | Yes |
| Auditor (human) | Audit store | Y | N | N | N | N | Yes |
| Administrator | Cluster control plane | Y | Y (break-glass, dual control, logged) | Y | Y (theoretically) | N | Restricted, alarmed |

Key fixes vs. the original design's implicit "use RBAC/Vault" hand-wave:
- **Short-lived leases scoped per session ID**, not per tenant-forever — a red-team credential from test #4 must not work for test #5 (prevents credential replay across sessions, closes a confused-deputy path where a stale token from an old session gets reused).
- **No principal has delete rights on the audit store**, including the broker and admins under normal operation — delete requires a separate, out-of-band, dual-signed break-glass procedure that is itself logged to a physically/logically separate system.
- **Confused-deputy check:** the broker must never accept "act on behalf of tenant X" without X's own credential in the request — otherwise a compromised blue sandbox could ask the broker to fetch something "for the audit system" and have the broker's elevated privilege used against it. Mitigate with **capability tokens scoped to a single action**, not ambient broker authority being invoked generically.

---

## K. LLM Isolation & Contamination Analysis

**"Clean and uncontaminated" — operational definition:** the model's observable behavior on test N must be statistically indistinguishable from behavior on a model that never processed tests 1..N-1, with respect to: system prompt, conversation history, any retrieval/embedding store, KV-cache, adapter/LoRA weights, and any tool/external state.

### Lifecycle: CREATE → INITIALIZE → TEST → VERIFY → DESTROY

- **CREATE:** Spin up a fresh model-serving instance (or fresh isolated inference session) from a pinned, hash-verified weight snapshot. No reuse of a "warm" instance that served a prior session **unless** cache/session state is provably reset (see VERIFY).
- **INITIALIZE:** Load canonical system prompt (hash-checked against the expected value — detects config drift), empty context, KV-cache cold, no tool state, no retrieval DB pre-populated for this session.
- **TEST:** Single-session inference only; session ID bound to this test and rejected on reuse. Context window strictly scoped to this session's turns — the broker constructs each request from scratch, never appends across sessions.
- **VERIFY:** Before releasing the instance back to a pool (if pooling for throughput), run an automated canary probe (a fixed, known prompt) and diff its output against the expected baseline hash; **any deviation invalidates the instance** and it is destroyed rather than reused. This is the actual mechanism that lets you *claim* "no cross-test contamination" instead of just asserting it.
- **DESTROY:** Full teardown of the VM/container, explicit memory scrubbing (zero GPU and CPU allocations — most ML serving frameworks do **not** do this by default, so this must be an explicit step, e.g., via driver-level memory reset or simply never reusing physical GPU memory without a reset between security-sensitive sessions), removal of any temp files, logs rotated out of the live instance.

**Answering "how do we prove a prior test didn't affect a later one":** (a) architecturally, via one-fresh-instance-per-session as the default (strongest, costliest); or (b) if pooling for cost reasons, via the canary-probe VERIFY step plus a signed attestation in the audit log stating "instance N passed canary check C before session S" — this converts an assumption into a testable, logged claim, per the rules of this review.

**Shared inference infra — can red request A influence blue-observed request B?** Yes, if: (1) prefix/KV-cache is shared (§G.6), (2) dynamic batching mixes both requests in the same forward pass and any implementation bug causes cross-request attention leakage (rare but a known class of serving-stack bugs), (3) GPU memory is reused without scrubbing. **If true isolation is required, use separate inference workers (separate GPU/VM) per active session for red and blue-observable evaluation runs.** If shared inference is kept for cost, the *minimum* required controls are: no prefix-cache sharing across the red/blue boundary, batching only within a single tenant/session, and canary-verified state reset between sessions.

---

## L. Evaluation Integrity

Distinguishing failure classes:

| Class | Signature | Detection method |
|---|---|---|
| **Model failure** (genuine safety finding) | Canary probe passes (environment healthy), request/response fully logged, no error/retry/timeout on the path | Correlate finding against a clean canary run in the same instance/session |
| **Infrastructure failure** | Network errors, timeouts, non-2xx broker responses, resource-quota throttling events in the audit log around the same timestamp | Audit log must record infra-layer events (throttle, timeout, retry) alongside evaluation events, not just the "logical" test outcome |
| **Test-harness failure** | Malformed request/response against schema, dataset-version mismatch, config-hash mismatch vs. expected | Schema validation + config hash-check logged per test; mismatch auto-flags the result as `HARNESS_ERROR`, not a finding |
| **Attacker-induced environmental effect** | Red team intentionally exhausts resources or manipulates timing to force a false "finding" (e.g., timeout that blue misreads as a jailbreak) | Resource-quota logs correlated with request; if red's own resource consumption spiked immediately pre-finding, flag for manual review before certifying |

**Required evidence before a finding is declared valid:** (1) matching canary-probe pass immediately before the session, (2) config/dataset/model hash all match expected values (logged), (3) no infra-layer error/retry/timeout recorded on the critical path, (4) resource usage within normal quota band (no contention spike), (5) full request/response pair independently reconstructable from the audit log. Absence of any of these downgrades the result to `UNVERIFIED`, not a certified finding — this is the actual mechanism, not a promise.

---

## M. Audit & Provenance

- **What's tracked per event:** test ID, tenant, actor (service identity, not human), timestamp (coarse + precise-but-sealed), config hash, model weight hash, container/VM image digest, dataset version hash, attack-artifact hash, defensive-artifact hash, execution environment descriptor (node, isolation tier used), resource allocation snapshot, network-policy version, result, and a hash chain link to the previous event.
- **Mechanism:** append-only, hash-chained (each entry includes `hash(prev_entry || this_entry_content)`), periodically anchored (e.g., a Merkle root of the last N entries signed and optionally published/timestamped externally — Sigstore Rekor-style transparency log is a good concrete reference architecture). Storage backend should be WORM (object-lock/immutability mode on the cloud object store), so even the storage admin cannot mutate past objects without leaving evidence (a new bucket version, itself logged).
- **Can an administrator silently modify evidence?** With WORM + external anchoring: **no**, not without the tamper being detectable — the anchored Merkle root published outside the mutable system would no longer match a re-computed root. Without external anchoring, a full-privilege cloud admin theoretically *can* mutate WORM settings themselves (it's a config, not a law of physics) — this must be stated explicitly as residual risk unless you add out-of-band anchoring (e.g., periodic root published to an external, separately-controlled system) or split-key/dual-control admin access to the object-lock policy itself.
- **Does the audit system leak red payloads to blue?** Only if a shared audit *reader* interface exists without per-tenant access control on read. Fix: **the audit store itself is write-only for tenants; only the broker and designated auditors have read access, and any auditor-facing disclosure UI applies the same redaction policy as the broker's post-`CONCLUDE` disclosure path** — i.e., the audit system is not a side door around the disclosure state machine.

---

## N. Observability Security

Monitoring is treated as a first-class leakage surface, not a passive add-on.

- **What's exposed to Red Team:** only its own resource metrics (bucketed, e.g., CPU usage in 10% bands, not exact values), its own session status (coarse phase enum), generic error class on failure. Nothing about blue's dashboards, alerts, or metrics — enforced by per-tenant metric namespacing (e.g., separate Prometheus scrape scopes with tenant-labeled RBAC, not just dashboard-level filtering which can be bypassed via the raw query API).
- **What's exposed to Blue Team:** symmetric — own metrics only, plus the post-`CONCLUDE` disclosure bundle via the broker (not via a monitoring backdoor).
- **What's exposed to Client (if applicable):** typically nothing during testing; aggregate, anonymized statistics post-program if contractually agreed.
- **What's exposed to Administrator:** full cross-tenant view, but every access itself logged to the audit system (an admin *viewing* cross-tenant data is itself a loggable, reviewable event — this closes the "trusted but unaccountable" gap).
- **What's exposed to Security Auditor:** full access via the same redaction-aware interface as disclosure, with all access logged.
- **Alert channel leakage:** a shared incident channel (e.g., one PagerDuty/Slack channel for "the whole platform") is a real, easily-missed leak — "an alert fired mentioning red's namespace" is content-bearing to blue if they're in the same channel. Fix: **per-tenant-scoped alert routing**, with only infra-level (non-content) alerts going to a shared platform-ops channel, and that channel's alert templates scrubbed of tenant-identifying payload content.

---

## O. Failure Scenarios (15+)

| # | Scenario | Blast radius | Containment | Detection | Recovery | Trustworthy after? |
|---|---|---|---|---|---|---|
| 1 | Red container compromised (RCE) | Red's own VM only, given Kata boundary | VM-level isolation stops host/lateral spread | seccomp/behavioral anomaly alert, canary probe on next model session | Destroy+recreate red sandbox, rotate red's short-lived creds | Yes, if audit shows no cross-boundary event logged |
| 2 | Blue container compromised | Blue's own VM only | Same as above | Same | Destroy+recreate, rotate creds | Yes, same condition |
| 3 | Model sandbox compromised | Model VM only; egress-denied so no exfil path | Zero-egress network policy | Canary probe fails on next check | Destroy instance, restore from verified weight snapshot | No — all sessions since last passing canary must be marked `UNVERIFIED` |
| 4 | Evaluation controller (broker) compromised | Potentially both tenants' visibility — worst case | Broker runs with least privilege itself (no ambient superuser to Vault, only per-request scoped leases); ideally broker logic is minimal and formally reviewable | Anomalous OPA-denial-bypass attempts logged; broker behavior monitored by an independent watchdog process | Full broker redeploy from known-good image, all sessions since last verified broker state hash flagged for re-review | No — this is the worst-case scenario and must be named as the single highest-value target in the write-up |
| 5 | Network policy failure (Cilium misconfig allows red→blue) | Direct cross-tenant channel opens | Defense-in-depth: mTLS + OPA still block at the application layer even if network layer fails | Network-policy drift detection (periodic diff against declared policy-as-code) | Roll back policy from git-tracked source of truth | Depends — any session during the window is `UNVERIFIED` until reviewed |
| 6 | Database (session-state store) failure | Broker loses ability to enforce state machine | Fail-closed: broker denies all cross-boundary requests if it can't confirm current session state | Health-check/heartbeat monitoring | Restore from replicated state store | Yes, if fail-closed held |
| 7 | Audit-store failure | Loss of ability to record new evidence | Broker fail-closed: refuses to advance session state if audit write fails (no unaudited actions permitted) | Write-ack timeout | Failover to replica/secondary WORM store | Yes — sessions during outage should be paused, not silently allowed |
| 8 | Container-runtime failure (Kata/host issue) | Affected tenant's sandbox down | Isolation means only that tenant's sessions pause | Orchestrator health checks | Reschedule on healthy node | Yes |
| 9 | Host compromise (hypervisor-level) | Potentially all VMs on that host | Node-level blast radius; mitigated by not co-locating red+blue on the same physical host where possible (anti-affinity rules) | Host-level intrusion detection (outside this PoC's normal scope, but should be noted) | Cordon+drain node, redeploy elsewhere, treat all sessions on that host as compromised | No — explicit worst case, name as residual risk requiring confidential computing for full mitigation |
| 10 | Cloud credential compromise (e.g., leaked IAM key) | Depends on key's scope — this is why least-privilege, short-lived, per-component IAM roles matter | Scoped roles limit blast radius to that component's resources only | Cloud provider's own credential-usage anomaly detection + audit log correlation | Revoke/rotate immediately, review all actions taken with that credential | Any actions taken under compromised cred must be reviewed/invalidated |
| 11 | Inference-server crash mid-session | That session's test aborted | Broker detects failed response, marks session `INFRA_FAILURE` not a finding | Health check / request timeout | Restart, re-run test with fresh instance | N/A for that session — correctly excluded from findings |
| 12 | Resource exhaustion (one tenant starves another via quota bug) | Evaluation validity — could produce false timing-based findings | Hard cgroup quotas prevent one tenant from consuming shared headroom; separate node pools if quotas alone insufficient | Resource-usage anomaly monitoring | Adjust quotas, re-run affected sessions | Affected sessions flagged `UNVERIFIED` |
| 13 | Malicious administrator | Could be severe — full access in a naive design | Dual-control break-glass, all admin actions logged to separate immutable channel, least-privilege even for admins (no single "god" account) | Out-of-band review of admin-action log | Revoke access, forensic review, potentially re-certify all findings touched | This is the scenario the "no protection" honesty section must be blunt about — a fully privileged insider is very hard to fully defend against without splitting trust across multiple people/orgs |
| 14 | Corrupted dataset (e.g., AdvBench mirror tampered) | Wrong test inputs used, false findings possible | Dataset pinned by hash, verified at load time | Hash mismatch at INITIALIZE | Reject and alert, re-fetch from verified source | Sessions using corrupted data auto-flagged `HARNESS_ERROR` |
| 15 | Corrupted/malicious container image | Backdoored sandbox behavior | Image digest pinning + signed images (cosign/Sigstore), admission-controller policy rejecting unsigned images | Signature verification failure at deploy time | Block deploy, alert | N/A — should never reach running state |
| 16 | Compromised dependency (supply-chain, e.g., a malicious PyPI package in the broker's image) | Depends on what the dependency touches — potentially broker-level compromise | SBOM + dependency pinning + vulnerability scanning in CI | SCA/vulnerability scan flags known-bad package | Rebuild from clean lockfile, redeploy | Any sessions run under the compromised build should be treated as scenario #4 (broker compromise) |

---

## P. Alternative Architectures

### Architecture A — Hardened Containers + Strict Network Segmentation
*(closest to the original proposal, refined)*
- Boundary: Linux namespaces + seccomp + AppArmor, no VM layer.
- Isolation strength: Moderate — depends entirely on host kernel integrity.
- Performance: Best (near-native, lowest overhead/latency).
- Cost: Lowest.
- Attack surface: Largest — shared kernel across all tenants is a standing risk.
- Verdict: Fastest to build for a hackathon, but weakest against the "compromised container" threat class this problem statement explicitly asks you to model. Reasonable only as a **fallback tier** for low-risk components (e.g., the observability stack), not for red/blue/model.

### Architecture B — Separate Inference Workers + Isolated Tenant Sandboxes
- Boundary: Kata/microVM per tenant *and* dedicated (non-shared) inference workers per active red/blue-observable session.
- Isolation strength: High — closes the KV-cache/batching channel (§G.6) structurally rather than via config.
- Performance: Worse — no cache reuse means higher latency and lower throughput; needs more GPU headroom.
- Cost: Higher (more GPU instances, lower utilization).
- Verdict: Best security-to-complexity ratio for the LLM-specific threats this problem statement is scored on. **This is the core of the recommended design.**

### Architecture C — MicroVM / Stronger Workload Isolation for Everything (incl. broker)
- Boundary: Firecracker/Kata for every component, including the broker and audit service, not just tenants.
- Isolation strength: Highest achievable without proprietary hardware.
- Performance: Meaningful overhead on the broker's hot path (every mediated call crosses a VM boundary).
- Operational complexity: Highest — more moving parts to deploy/debug in a hackathon timeframe.
- Verdict: The "gold standard" reference to describe in the write-up, but **descope for the actual PoC** to the tenant workloads only (Architecture B), naming full-stack VM isolation as roadmap/future work — this keeps the demo buildable while showing you understand the ceiling.

### Architecture D — Ephemeral Per-Test Environments
- Boundary: Every single test session gets a brand-new, from-scratch environment (all components, not just the model) destroyed immediately after.
- Isolation strength: Very high for contamination (§K) — literally nothing persists to leak.
- Performance: Poor — cold-start cost per test is significant, kills throughput for a red team running hundreds of probes.
- Verdict: Excellent for **high-stakes/final certification runs**, bad as the default mode for iterative red-teaming. Recommend as a selectable "certified mode" layered on top of Architecture B, not a replacement for it.

### Architecture E — Hybrid (Recommended)
Combine B (dedicated inference workers per session, no cross-tenant cache) + D as an optional "certified" strict mode + A's lightweight namespace/seccomp hardening applied *underneath* Kata as defense-in-depth (belt-and-suspenders, not either/or) + C's principles (full VM isolation) documented as the production target once resources allow. This hybrid is what's built out in §Q.

---

## Q. Revised Architecture

```
                         ┌───────────────────────────────────────────┐
                         │         CONTROL PLANE (min. privilege)     │
                         │  ┌───────────┐   ┌───────────┐             │
                         │  │  OPA PDP   │   │  Vault     │             │
                         │  └─────▲─────┘   └─────▲─────┘             │
                         │        │policy check     │scoped lease      │
                         │  ┌─────┴─────────────────┴────┐            │
                         │  │   BROKER / STATE MACHINE    │            │
                         │  │  SETUP→RED→INFER→EVAL→      │            │
                         │  │  BLUE→CONCLUDE→DISCLOSE     │            │
                         │  │  (minimal, reviewable code) │            │
                         │  └──┬───────────┬───────────┬──┘            │
                         └─────┼───────────┼───────────┼───────────────┘
                mTLS(SPIFFE)   │           │           │  mTLS(SPIFFE)
              ┌─────────────────┘           │           └─────────────────┐
              │                             │                             │
    ┌─────────▼─────────┐        ┌──────────▼──────────┐        ┌─────────▼─────────┐
    │  RED SANDBOX       │        │  DEDICATED MODEL     │        │  BLUE SANDBOX      │
    │  Kata microVM       │        │  INFERENCE WORKER    │        │  Kata microVM       │
    │  cgroup: cpuset A    │        │  (no shared KV-cache  │        │  cgroup: cpuset B    │
    │  egress: broker only │        │  across sessions)     │        │  egress: broker only │
    │  fresh rootfs/session│        │  fresh session/CREATE-│        │  fresh rootfs/session│
    │                      │        │  DESTROY lifecycle    │        │                      │
    └──────────┬───────────┘        │  egress: DENY ALL     │        └──────────┬───────────┘
               │write-only          └───────────┬────────────┘                   │write-only
               │                                 │canary-verified                 │
               │                                 │                                │
               └───────────────┐   ┌─────────────┘   ┌────────────────────────────┘
                                ▼   ▼                 ▼
                     ┌───────────────────────────────────────┐
                     │     AUDIT / PROVENANCE (WORM, hash-    │
                     │     chained, externally anchored)      │
                     │     tenant write-only / auditor read   │
                     └───────────────────────────────────────┘

        Per-tenant-scoped OBSERVABILITY (bucketed metrics, no cross-tenant read) — sidecar to each box
        Anti-affinity: RED and BLUE never co-scheduled on the same physical host where feasible
```

Key structural decisions vs. the original:
1. **Uniform Kata isolation** across red, blue, and model (not asymmetric gVisor-for-red-only).
2. **Dedicated, non-pooled inference worker per active session** — closes the KV-cache/batching channel structurally, at an accepted latency/cost cost, matching Architecture B/E.
3. **Zero egress from the model sandbox**, full stop — the model cannot exfiltrate anywhere even if compromised.
4. **Audit store is write-only for tenants**, externally anchored, so it can't become a leak channel or a silently-mutable record.
5. **Broker kept intentionally minimal** (small, reviewable codebase, ideally formally specified state machine) *because* it's the named single point of trust — reducing its complexity is itself a mitigation for scenario O.4.
6. **Anti-affinity scheduling** for red/blue to reduce the resource-contention side channel (§G.2) at the infrastructure level, not just via quotas.

---

## R. Security Controls Map

| Threat | Control |
|---|---|
| Direct red↔blue/model comms | Mandatory mediation + default-deny CNI + mTLS |
| Container escape | Kata VM boundary (all tenants, uniformly) |
| Credential theft/replay | Per-session short-lived Vault leases, SPIFFE workload identity |
| Cross-tenant timing inference | Bucketed/quantized cross-tenant-visible timing, dedicated inference workers |
| KV-cache/prefix-cache leakage | No cross-session cache sharing; dedicated worker per session |
| Resource-contention covert channel | Disjoint cgroups + anti-affinity scheduling |
| Metadata-service pivot post-escape | Network + IAM + seccomp denial of IMDS, redundantly |
| Audit tampering | WORM storage + hash chain + external anchoring |
| Audit-as-leak-channel | Write-only tenant access, redaction-aware auditor read path |
| Contaminated model state | CREATE→INITIALIZE→TEST→VERIFY→DESTROY lifecycle + canary probes |
| False findings from infra noise | Evaluation-integrity evidence checklist (§L) |
| Malicious insider | Dual-control break-glass, all admin access logged separately |
| Supply-chain compromise | Signed images (cosign), SBOM, pinned hashes, admission control |
| Observability leakage | Per-tenant metric namespacing, scrubbed alert routing |
| Broker compromise (worst case) | Minimal broker codebase, least-privilege broker credentials, independent watchdog |

---

## S. PoC Demonstration Plan

| Claim | Test |
|---|---|
| Red cannot access blue's data | Attempt direct red→blue connection at network layer; expect connection refused; attempt to forge a broker request claiming blue's identity without blue's cert; expect mTLS rejection |
| Blue cannot see red payload before conclusion | Query broker for session content during `RED_TURN`; expect OPA-denied response; repeat after `CONCLUDE`; expect (redacted) success |
| Unauthorized network connections fail | Run `nmap`/connection-attempt script from inside red sandbox against blue's service IP and cloud metadata IP; expect all fail uniformly |
| Container capabilities restricted | From inside a tenant sandbox, attempt `mount`, `ptrace` another process, and read `/proc/<broker-pid>`; expect all denied/absent (Kata gives no visibility into other VMs' `/proc` at all) |
| Resource quotas hold under load | Saturate red's cgroup CPU quota; measure blue's independently-scheduled workload latency; expect no measurable change (validates anti-affinity + disjoint cpuset) |
| No cross-session model contamination | Run session 1 with a distinctive context; run session 2 fresh; probe session 2 for any trace of session 1's content; expect none; verify canary-probe hash matches baseline |
| Tamper-evident audit | Attempt to modify a past audit entry directly in storage; recompute hash chain; expect mismatch detected; attempt via admin path; expect it's logged separately and flagged |
| Boundary-violation detection | Deliberately misconfigure a network policy to allow red→blue; run policy-drift detector; expect alert fired referencing the specific rule diff |
| Failure recovery | Kill the model sandbox mid-session; confirm broker marks session `INFRA_FAILURE` (not a finding), confirm audit log records the event, confirm system recovers with a fresh instance on next session |

---

## T. Attack Simulation Plan

1. **Red-team the isolation itself:** from inside the red sandbox, attempt (a) direct connection to blue's known service name, (b) DNS lookup for internal service names, (c) IMDS access, (d) `/proc` enumeration for other tenants, (e) shared-volume probing. Every attempt should fail and be logged.
2. **Timing side-channel probe:** from blue sandbox, send a burst of timed requests to the broker during a red-team session of known complexity; attempt to correlate response latency with red's payload size; measure whether bucketing (§G.1) reduces correlation below a defined significance threshold.
3. **KV-cache probe:** submit an identical prefix from both red and blue sessions in quick succession against the model worker; measure response latency; confirm no cache-hit speedup indicates shared state (validates §G.6 mitigation).
4. **Confused-deputy attempt:** from a compromised blue sandbox, attempt to have the broker act on red's behalf without red's credential; expect rejection.
5. **Audit tamper attempt:** as described in §S; also attempt to delete the WORM bucket's lock policy itself via a stolen admin-scoped credential, to test whether dual-control actually blocks a single compromised admin identity.
6. **Chaos/failure injection:** kill each component (broker, audit store, model worker, Vault) one at a time under active sessions; verify fail-closed behavior everywhere (no component defaults to "allow" when it can't verify policy).
7. **Supply-chain simulation:** attempt to deploy an unsigned/modified container image; expect admission-controller rejection.

---

## U. Residual Risk

| Threat | Protection | Remaining Exposure | Preconditions | Residual Risk |
|---|---|---|---|---|
| Direct cross-tenant network access | Strong (default-deny CNI + mTLS) | Misconfiguration during deploy | Policy-as-code not enforced in CI | Low, if drift-detected |
| Container/kernel escape | Strong (Kata VM boundary) | Hypervisor 0-day | Attacker has kernel-level exploit for the specific hypervisor | Low-medium, unavoidable without confidential computing |
| Hardware side channels (cache timing, Spectre-class) | Partial (disjoint cpusets, anti-affinity) | Same-host residual leakage; not addressed without SEV-SNP/TDX | Shared physical host | **Medium — explicitly not solved by this PoC** |
| KV-cache/prefix-cache leakage | Strong (dedicated per-session workers) | None if strictly enforced; throughput cost accepted | — | Low |
| Timing-based inference (coarse) | Partial (bucketing) | Patient, high-volume statistical adversary can still extract low-bandwidth signal | Many repeated probes allowed | Medium |
| Compromised broker | Weak-to-moderate (minimal codebase, least privilege) | Full cross-tenant visibility if actually compromised | Broker RCE | **High — single largest named risk** |
| Malicious fully-privileged insider | Partial (dual control, logging) | A sufficiently privileged single actor with control over the logging infra too can still act undetected in the worst case | Insider controls both target system and its audit trail | High, fundamentally hard without organizational (not just technical) controls |
| Output-based steganographic exfiltration by the model | Weak (normalization only) | Sophisticated encoding may survive normalization | Model has motive/capability to encode | Medium-high — open research problem, not solved here |
| Supply-chain compromise | Moderate (signing, SBOM, pinning) | Zero-day in a pinned dependency itself | Vulnerability undiscovered at pin time | Medium |
| Cloud provider/insider access | Not protected | Full | Out of scope for any tenant-level architecture | Out of scope, named explicitly |

**Future work:** confidential computing (AMD SEV-SNP / Intel TDX) for hardware-enforced isolation against same-host side channels; formal verification of the broker's state machine and OPA policy set; multi-party/threshold disclosure decisions so no single broker instance has unilateral cross-tenant visibility; research-grade steganography detection on model outputs.

---

## V. Implementation Roadmap

- **Phase 1 — Foundation:** repo scaffolding, IaC (policy-as-code for network rules), CI with image signing/SBOM, base Kata-enabled cluster.
- **Phase 2 — Isolation:** deploy red/blue/model as separate Kata microVMs with disjoint cgroups; verify with escape-attempt tests (§T.1).
- **Phase 3 — Network Security:** Cilium default-deny policies, SPIFFE/mTLS identities, IMDS blocking; verify with connection-attempt tests.
- **Phase 4 — LLM Isolation:** dedicated per-session inference workers, cache-sharing disabled, CREATE→DESTROY lifecycle with canary probes.
- **Phase 5 — Auditability:** hash-chained WORM audit store, broker write path, external anchoring stub.
- **Phase 6 — Attack Simulation:** run the full §T plan against the deployed system; fix findings.
- **Phase 7 — Hardening:** bucketed observability, canonicalized error taxonomy, anti-affinity scheduling, dual-control break-glass.
- **Phase 8 — Final Validation:** run §S demonstration plan end-to-end; produce the residual-risk table with real measured numbers (latency overhead, throughput cost) rather than estimates.

---

## W. Final Pre-Deployment Checklist

- [ ] All tenant workloads run under the same isolation tier (no asymmetric hardening).
- [ ] Default-deny network policy verified with live connection-attempt tests, not just config review.
- [ ] Cloud metadata endpoint blocked at network, IAM, and seccomp layers independently.
- [ ] No shared volumes/sockets between any two tenant workloads.
- [ ] KV-cache/prefix-cache sharing disabled across the red/blue boundary.
- [ ] Canary-probe verification wired into the model instance lifecycle before every reused session.
- [ ] Audit store is genuinely append-only (delete/update verbs removed from the API surface, not just access-denied).
- [ ] Audit store externally anchored (or explicitly flagged as not, in residual risk).
- [ ] Cross-tenant-visible timing/metrics are bucketed, not exact.
- [ ] Error messages returned across tenant boundaries use a fixed canonical taxonomy.
- [ ] Admin access requires dual control and logs to a separate channel.
- [ ] Container images are signed and pinned by digest; unsigned images rejected by admission control.
- [ ] Every security claim in the write-up has a corresponding test from §S/§T that was actually run.
- [ ] Residual-risk table reflects measured (not assumed) results where possible.

---

## X. Final "What We Almost Missed"

- **The broker's own request logging can itself be a side channel** if log lines for red and blue sessions are interleaved in a single shared log stream visible to any shared tooling — must be tenant-partitioned even at the raw log-shipping layer, not just at the dashboard layer.
- **Session IDs themselves can leak volume/ordering information** if globally monotonic — a blue team that can infer "session IDs jumped by 40 while I was waiting" learns red ran 40 tests. Use per-tenant-scoped, non-sequential (random/UUID) identifiers.
- **The "fresh rootfs per session" control can create a *detectable* timing signature** (VM boot time) that itself is a coarse side channel about session cadence — worth noting even though the actual info content is very low.
- **A compromised model could deliberately trigger error conditions or retries as a low-bandwidth encoding channel** (e.g., forcing 3 retries to signal "3") — the evaluation-integrity mechanism in §L partially catches this by flagging retry-heavy sessions, but this is a genuinely subtle channel that a first-pass design would miss entirely.
- **Anti-affinity scheduling for red/blue helps side channels but can itself leak scheduling metadata** (e.g., which nodes exist, cluster size) to an attacker who can query the orchestrator API — the orchestration control plane's own API needs the same default-deny tenant scoping as everything else, which is easy to forget because it "isn't part of the test path."
- **Dual-control break-glass is only as strong as the second controller's independence** — if both approvers report to the same person or share credentials operationally, "dual control" is theater. This is an organizational, not technical, gap and should be stated plainly rather than assumed solved by having two buttons.
