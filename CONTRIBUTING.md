# Contributing to Bayora

Thank you for your interest in contributing to the **Bayora Secure AI Safety Testing Architecture Platform**!

Bayora is an adversarial testing infrastructure designed to run mutually distrusting Red Team attackers, Blue Team defenders, and Subject-Under-Test LLMs under strict, mathematically provable isolation.

---

## 🛠️ Development Setup

1. **Fork and Clone** the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/bayora-secure-ai-safety.git
   cd bayora-secure-ai-safety
   ```

2. **Install Dependencies**:
   ```bash
   npm install
   ```

3. **Run the Local Dev Platform**:
   ```bash
   npm start
   ```
   Access the dashboard at `http://localhost:3000`.

---

## 🧪 Testing Guidelines

Before submitting any Pull Request, you **must** ensure that all tests pass cleanly:

1. **Section S PoC Verification Suite**:
   ```bash
   npm test
   ```
   Validates all 9 proof-of-concept claims:
   - Mandatory mediation
   - Gated disclosure state machine
   - Egress denial & IMDS blocking (modeled CNI)
   - Kata microVM capabilities restriction (modeled target architecture)
   - Anti-affinity resource isolation (modeled topology)
   - Cold KV-cache & automated canary probes
   - SHA-256 hash chaining & Merkle root integrity
   - GitOps policy drift detection
   - Evaluation integrity failure classification

2. **Subsystems & Weight Integrity Unit Tests**:
   ```bash
   npm run test:unit
   ```
   Validates weight integrity verification and state-machine/vault/mitigations branch logic.

3. **Runtime Worker-Threads Isolation Unit Tests**:
   ```bash
   npm run test:isolation
   ```
   Verifies real runtime V8 isolate memory boundaries, independent secret fingerprints, and enforced V8 heap `resourceLimits` rejection.

4. **Section T Adversarial Attack Simulations**:
   ```bash
   npm run test:attacks
   ```
   Executes the 7 adversarial simulations against container boundaries, timing side-channels, prefix-cache sharing, confused-deputy attacks, and audit log tampering.

5. **Full Suite & Coverage Verification**:
   ```bash
   npm run test:all
   npm run test:coverage
   ```

---

## ⚔️ Contributing New Attack Probes (Red Team)

To contribute a new adversarial probe or dataset:
1. Ensure attack vectors do not contain dangerous, weaponized, or illegal materials. Use standardized benchmark taxonomies (AdvBench, HarmBench, JailbreakBench).
2. Add the test case into [`src/datasets/benchmark_registry.js`](./src/datasets/benchmark_registry.js).
3. If simulating a novel infrastructure side-channel or isolation bypass, implement an adversarial simulation in [`src/attacks/simulation_suite.js`](./src/attacks/simulation_suite.js).

---

## 🛡️ Contributing New Defenses (Blue Team)

1. Defenses should be implemented as sandboxed filters, classifiers, or guardrails within the Blue Sandbox scope.
2. Defenses must **never** assume direct network visibility into the Red Sandbox.
3. All defense verdicts must adhere to the schema:
   ```json
   {
     "isBlocked": true,
     "defenseVerdict": "ADVERSARIAL_DETECTED",
     "timestamp": "ISO_8601"
   }
   ```

---

## 📜 Pull Request Process

1. Create a feature branch: `git checkout -b feature/my-new-defense`
2. Commit with clear, descriptive messages following conventional commits (`feat:`, `fix:`, `docs:`, `test:`).
3. Verify that all test suites pass with 100% success (`npm run test:all`).
4. Submit the PR using the provided Pull Request Template.
