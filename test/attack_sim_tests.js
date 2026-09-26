/**
 * Bayora Standalone CLI Attack Simulation Runner
 * Validates the 7 Attack Simulations in Section T of bayora-redteam-review.md
 */

const AttackSimulationSuite = require('../src/attacks/simulation_suite');

async function run() {
  console.log('========================================================================');
  console.log('   BAYORA ADVERSARIAL ATTACK SIMULATION SUITE: 7 SCENARIOS (§T)        ');
  console.log('========================================================================\n');

  const suite = new AttackSimulationSuite();
  const results = await suite.runAllAttackSimulations();

  let allPassed = true;

  results.forEach((sim) => {
    const symbol = sim.mitigationCertified ? '🛡️ MITIGATED' : '⚠️ VULNERABLE';
    console.log(`[${symbol}] [${sim.simId}] ${sim.name}`);
    if (sim.probes) {
      console.log('       Timing Probes:', sim.probes.map(p => `${p.payloadType}: raw=${p.rawMs}ms -> quantized=${p.quantizedMs}ms`).join(', '));
    }
    if (sim.attacks) {
      console.log('       Interceptions:', sim.attacks.map(a => `${a.target}: ${a.result}`).join(' | '));
    }
    if (sim.rootsDiverged !== undefined) {
      console.log(`       Tamper Evidence: Root Divergence Detected=${sim.rootsDiverged}, Merkle Valid=${!sim.tamperDetected}`);
    }
    if (sim.canaryPassed !== undefined) {
      console.log(`       Canary Alarm: Triggered=${sim.alarmRaised}, Status=${sim.workerStatus}`);
    }
    if (!sim.mitigationCertified) {
      allPassed = false;
    }
  });

  console.log('\n------------------------------------------------------------------------');
  if (allPassed) {
    console.log(`SUCCESS: All ${results.length} adversarial attack simulations intercepted & mitigated!`);
  } else {
    console.error(`FAILURE: One or more attack simulations found vulnerabilities.`);
    process.exit(1);
  }
  console.log('========================================================================\n');
}

run().catch(err => {
  console.error('Attack simulation runner error:', err);
  process.exit(1);
});
