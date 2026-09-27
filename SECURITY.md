# Security Policy

The Bayora team takes the security of the AI safety testing infrastructure very seriously.

Because Bayora explicitly hosts mutually adversarial workloads, testing and finding security bypasses is fundamental to our mission. However, any security vulnerability in the control plane, broker mediation, or audit immutability should be reported responsibly.

---

## 🛡️ Supported Versions

| Version | Supported |
|---|:---:|
| 2.x (Worker-Threads Enforced + Kata/eBPF Target Redesign) | :white_check_mark: |
| 1.x (Legacy bare-container skeleton) | :x: |

---

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability in the Bayora platform, please report it via coordinated disclosure:

1. **Do not** file a public GitHub issue.
2. Email your report to: `itz.ansh02@gmail.com` (or submit a Private Vulnerability Advisory on GitHub).
3. Include:
   - Component affected (Broker, OPA PDP, Vault Authority, Dedicated Worker, or WORM Audit Store).
   - Detailed attack vector and reproduction steps.
   - Proof of Concept (PoC) script demonstrating cross-tenant leakage, tamper without detection, or container breakout.
4. The security team will acknowledge receipt within 48 hours and provide a remediation timeline.

---

## 🎯 Scope & Expected Boundaries

### In Scope
- Cross-tenant data leakage between Red and Blue sandboxes prior to `CONCLUDE`.
- Undetected tampering with past WORM audit records.
- Confused-deputy privilege escalation in the Broker.
- Token replay across different sessions.
- In-memory contamination across model-serving sessions bypassing automated canary verification.
- Cross-tenant timing inference leaking payload category through the 250ms quantizer.

### Out of Scope / Residual Risks (§U)
- **Hypervisor 0-day**: Host breakout against the underlying Linux/KVM kernel outside of Kata microVM protections (target architecture; not yet running in this single-process PoC).
- **Hardware-level side channels**: Cache timing attacks (Spectre/Meltdown) when co-located without confidential computing (AMD SEV-SNP or Intel TDX).
- **Colluding insiders**: A cloud root administrator with physical/console access who can reconfigure IAM and WORM storage buckets out-of-band.
