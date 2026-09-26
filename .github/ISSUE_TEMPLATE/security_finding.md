---
name: Security Finding / Adversarial Bypass
about: Report a cross-tenant leakage vector, isolation flaw, or side-channel
title: '[SECURITY FINDING] '
labels: security, red-team
assignees: ''
---

> **CRITICAL**: If this finding impacts production credentials or live systems, please refer to [SECURITY.md](../SECURITY.md) to report privately via email.

**Finding Classification**
- [ ] Cross-tenant data leakage (Red ↔ Blue before CONCLUDE)
- [ ] Undetected WORM audit log tampering
- [ ] Confused-deputy privilege escalation
- [ ] Cross-session token replay or lifecycle contamination
- [ ] Timing or resource side-channel bandwidth bypass
- [ ] Container / microVM capability breakout

**Threat Model Impact**
- **Affected Principal**: [e.g. Red Sandbox, Blue Sandbox, Model Worker, Broker]
- **Threat Scenario from §O**: [e.g. Scenario #1, Scenario #4, Scenario #6]
- **Severity**: [Low / Medium / High / Critical]

**Proof of Concept (PoC)**
Provide the minimal reproduction script or payload sequence:
```javascript
// PoC exploit script
```

**Observed vs Expected Result**
- **Observed**: [What the system permitted or leaked]
- **Expected**: [What policy rule or boundary should have denied the request]

**Proposed Remediation**
Describe any policy rules, CNI modifications, or state machine transitions that mitigate this vector.
