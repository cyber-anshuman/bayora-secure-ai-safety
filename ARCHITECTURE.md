# Bayora Architecture Specification & Security Design

> **Technical Reference & Threat Modeling Specification**  
> Based on [`bayora-redteam-review.md`](./bayora-redteam-review.md).

---

## 1. System Engineering & Trust Boundaries

The fundamental architectural objective of Bayora is:

> **How to run three mutually distrusting, actively adversarial parties — Red Team (Attacker), Blue Team (Defender), and Subject-Under-Test LLM — concurrently on shared infrastructure, ensuring zero unauthorized information leakage, and later cryptographically proving the outcome to a third-party auditor.**

```
 ┌─────────────────────────────────────────────────────────────────────┐
 │                          CLOUD / HOST (untrusted-by-default)        │
 │  ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌────────────────┐ │
 │  │ RED VM    │   │ BLUE VM   │   │ MODEL VM  │   │ AUDIT (WORM)   │ │
 │  │ (Kata)    │   │ (Kata)    │   │ (Kata/GPU)│   │ append-only    │ │
 │  └─────┬─────┘   └─────┬─────┘   └─────┬─────┘   └────────┬───────┘ │
 │        │  mTLS         │ mTLS          │ mTLS             │sign-only│
 │        └──────────────►│◄──────────────┘                  │         │
 │                 ┌───────────────┐                         │         │
 │                 │  BROKER /     │─────────────────────────┘         │
 │                 │  ORCHESTRATOR │  (Mandatory Mediation Hub)        │
 │                 │  + OPA PDP    │                                   │
 │                 └───────┬───────┘                                   │
 │                         │                                           │
 │                 ┌───────▼───────┐                                   │
 │                 │ VAULT (leases)│                                   │
 │                 └───────────────┘                                   │
 └─────────────────────────────────────────────────────────────────────┘
```

### Trust Classification
- **Untrusted, Actively Adversarial**: Red Team sandbox, Blue Team sandbox, Client LLM outputs.
- **Trusted Root of Least Privilege**: Broker/State Machine Orchestrator, OPA Policy Engine, Vault Authority.
- **Trusted Root of Integrity**: WORM Append-Only Audit Store & Merkle Root Anchoring.
- **Assumed Hostile**: Underlying Cloud Hypervisor / Host (anti-affinity + hardware isolation required).

---

## 2. Core Isolation Primitives

### 2.1 Uniform Kata microVM Boundaries (§H)
- Standard Linux containers share the host kernel. In Bayora, **all three workloads** (Red, Blue, Model) run inside isolated hardware-virtualized **Kata Containers** (microVMs).
- Kernel capabilities are dropped:
  - `CAP_NET_RAW` dropped (prevents raw packet sniffing).
  - `CAP_SYS_ADMIN` dropped (prevents filesystem mount / pivot).
  - `CAP_SYS_PTRACE` dropped (prevents cross-process memory introspection).
- Read-only rootfs with ephemeral `tmpfs` per session; Docker socket is **never** mounted.

### 2.2 Cilium eBPF Default-Deny Networking (§I)
- All network traffic is denied by default at the eBPF layer.
- Permitted connections require mTLS and are strictly point-to-point:
  - `RED → BROKER`: Allowed (mTLS, scoped capability token).
  - `BLUE → BROKER`: Allowed (mTLS, scoped capability token).
  - `BROKER → MODEL`: Allowed (mediated inference requests only).
  - `RED → BLUE`: **DENIED** (mandatory mediation).
  - `RED → MODEL` / `BLUE → MODEL`: **DENIED** (mandatory mediation).
  - `MODEL → EXTERNAL`: **DENIED** (zero egress prevents steganographic exfiltration).
  - `ANY → 169.254.169.254 (IMDS)`: **DENIED** (prevents post-escape cloud credential theft).

---

## 3. Dedicated Model Inference & Canary Lifecycle (§K)

To prevent cross-session contamination via warm KV-cache or adapter state:

```
CREATE ➔ INITIALIZE ➔ TEST ➔ VERIFY ➔ DESTROY
```

1. **CREATE**: Instantiate a dedicated inference worker bound to a single session UUID.
2. **INITIALIZE**: Verify the hash of pinned model weights (`e3b0c442...`) and system prompt. Guarantee cold, empty KV-cache.
3. **TEST**: Execute the single isolated evaluation turn.
4. **VERIFY (Automated Canary Probe)**: Run a deterministic canary prompt (`CANARY_PROBE_V1`). If output deviates from `CANARY_BASELINE_HASH`, worker state is flagged `CONTAMINATED_INSTANCE` and immediately purged.
5. **DESTROY**: Scrub GPU/CPU memory allocations, delete ephemeral files, and tear down instance.

---

## 4. Evaluation Integrity 5-Factor Checklist (§L)

To eliminate false positive findings caused by environmental jitter:

| Factor | Verification Criterion | Failure Classification |
|---|---|---|
| **1. Canary Probe** | Automated canary probe hash matches expected baseline | `HARNESS_ERROR_CONTAMINATED_MODEL` |
| **2. Artifact Hashes** | Model weights, config, and dataset hashes match golden values | `HARNESS_ERROR_CONFIG_DRIFT` |
| **3. Clean Infra Path** | Zero timeouts, retries, or 5xx connection drops | `INFRA_FAILURE` |
| **4. Quota Band** | CPU peak <90% and Memory peak <90% (no contention spike) | `ATTACKER_INDUCED_RESOURCE_ANOMALY` |
| **5. Audit Reconstructability** | Full request/response hash-chained in WORM log | `UNVERIFIED` |

---

## 5. Cryptographic Provenance & WORM Audit (§M)

- **SHA-256 Hash Chaining**:
  $$H_i = \text{SHA256}(H_{i-1} \parallel \text{Timestamp} \parallel \text{Tenant} \parallel \text{Actor} \parallel \text{EventType} \parallel \text{PayloadHash} \parallel \text{Details})$$
- **Merkle Tree Anchoring**: Leaves are periodically hashed up into a Merkle root and anchored to simulate Sigstore/Rekor transparency logs.
- **Tenant Write-Only**: Red and Blue sandboxes can submit evidence to the audit log, but querying/reading is strictly denied (`E_AUDIT_WRITE_ONLY`).

---

## 6. Side-Channel Analysis & Mitigations (§G, §N)

- **Timing Channel (§G.1)**: Variable execution latencies are quantized into uniform 250ms buckets, significantly compressing statistical timing correlation.
- **Canonical Error Taxonomy (§G.8)**: Internal exceptions and stack traces are translated to fixed, generic codes (`SEC_ERR_01`, `RES_ERR_01`, `NET_ERR_01`).
- **Telemetry Namespacing (§N)**: Metrics are bucketed into 10% ranges (e.g. 40%-50%) and isolated by tenant namespace.
- **Anti-Affinity Scheduling (§G.2)**: Red and Blue workloads are allocated to disjoint NUMA domains and physical CPU sets (`Node-A cpuset:0-3` vs `Node-B cpuset:4-7`).
