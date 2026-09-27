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

### Target Architecture vs. PoC Implementation
*Note on PoC scope:* The architecture diagrams and component specifications herein represent the **target production architecture**. In this repository's standalone Node.js demonstration:
- **Fully / Partially Enforced in PoC**: Vault HMAC capability tokens (`vault_authority.js`), SHA-256 hash-chained WORM audit log with Merkle tree verification (`worm_store.js`), centralized policy decision logic (`opa_pdp.js`), 5-factor evaluation integrity evaluation (`integrity.js`), and **runtime memory isolation via Node.js `worker_threads` with enforced `resourceLimits` (`worker_isolation.js`, `tenant_sandboxes.js`)** providing real V8 isolate and heap separation for Red and Blue processing logic (verified via `test/worker_isolation.test.js`).
- **Simulated / Policy-Modeled in PoC**: Physical Kata microVM hypervisor isolation (modeled via `tenant_sandboxes.js` configuration metadata), Cilium eBPF network filtering (modeled via `opa_pdp.js` allow/deny logic), anti-affinity NUMA scheduling (modeled via `mitigations.js` lookup tables), and deterministic scripted inference (modeled in `inference_worker.js`). In production, these interfaces bind to real hypervisors, kernel eBPF hooks, Kubernetes topology managers, and dedicated GPU LLM endpoints.

---

## 2. Core Isolation Primitives

### 2.1 Uniform Kata microVM Boundaries (§H)
- Standard Linux containers share the host kernel. In the Bayora target architecture, **all three workloads** (Red, Blue, Model) are modeled to run inside isolated hardware-virtualized **Kata Containers** (microVMs). While the physical hypervisor boundary remains modeled in this PoC, Red and Blue's actual processing now runs in separate Node.js `worker_threads` V8 isolates with enforced `resourceLimits` (memory caps: 64MB/128MB) — providing real memory isolation with no shared object graph, though still short of kernel, filesystem, or network namespace separation.
- Kernel capabilities are dropped in target configuration:
  - `CAP_NET_RAW` dropped (prevents raw packet sniffing).
  - `CAP_SYS_ADMIN` dropped (prevents filesystem mount / pivot).
  - `CAP_SYS_PTRACE` dropped (prevents cross-process memory introspection).
- Read-only rootfs with ephemeral `tmpfs` per session; Docker socket is **never** mounted (target architecture specification).

### 2.2 Cilium eBPF Default-Deny Networking (§I — Modeled in PoC)
- In the target architecture, all network traffic is denied by default at the eBPF layer (modeled in this PoC via centralized PDP decision logic rather than live kernel eBPF bytecode).
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
- **Anti-Affinity Scheduling (§G.2 — Modeled in PoC)**: Red and Blue workloads are designed for placement on disjoint NUMA domains and physical CPU sets (`Node-A cpuset:0-3` vs `Node-B cpuset:4-7`), modeled via topology assignment lookup rather than active kernel cgroup/NUMA pinning.

---

## 7. Production Hardening Roadmap

To transition this reference implementation from a single-process Node.js demonstration (which currently enforces runtime V8 `worker_threads` memory separation, HMAC capability tokens, and cryptographic WORM verification) to an enterprise-grade cloud-native deployment:
1. **Physical MicroVM Isolation**: Replace the Node.js `worker_threads` runtime sandbox runner with hardware-virtualized **Kata Containers (v2) on Cloud-Hypervisor**, binding Red, Blue, and Model workloads to dedicated guest kernels with dropped Linux capabilities (`CAP_NET_RAW`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`) and ephemeral, read-only root filesystems.
2. **Kernel-Level Network Segmentation**: Replace in-process PDP socket checks with compiled **Cilium eBPF network policies** enforced directly at the host socket layer (`sockops` / `cgroup`), physically blocking direct peer-to-peer inter-pod routing (`Red ↔ Blue`, `Red ↔ Model`, `Blue ↔ Model`), IMDS metadata endpoints (`169.254.169.254`), and Model internet egress.
3. **External Policy & Secrets Daemons**: Transition in-process policy evaluation and HMAC authority to an external **Open Policy Agent (OPA) / Rego** sidecar daemon and **HashiCorp Vault / SPIFFE-SPIRE** mTLS service identity mesh with automated short-lived certificate rotation.
4. **Hardware Topology & Anti-Affinity Scheduling**: Transition the static lookup tables in `mitigations.js` to active **Kubernetes CPU Manager (`static` policy)** and NUMA-aware Topology Manager allocations, physically scheduling adversarial pods across disjoint NUMA nodes, distinct L3 cache slices, and non-overlapping CPU cores.
5. **Hardware-Isolated Inference Serving**: Point the Broker's model dispatch interface from the simulated `inference_worker.js` to a hardened, dedicated **vLLM / TGI** serving instance running inside a confidential GPU enclave (e.g. NVIDIA H100 Confidential Computing) with strict per-session KV-cache purges and automated golden weight verification.
