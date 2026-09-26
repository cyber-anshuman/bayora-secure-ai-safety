/**
 * Bayora Standalone CLI PoC Test Runner
 * Validates the 9 claims in Section S of bayora-redteam-review.md
 */

const AttackSimulationSuite = require('../src/attacks/simulation_suite');

async function run() {
  console.log('========================================================================');
  console.log('   BAYORA SECURE AI SAFETY TESTING ARCHITECTURE: POC TEST SUITE (§S)   ');
  console.log('========================================================================\n');

  const suite = new AttackSimulationSuite();
  const results = await suite.runAllPocTests();

  let allPassed = true;

  results.forEach((r, idx) => {
    const symbol = r.passed ? '✓ PASS' : '✗ FAIL';
    console.log(`[${symbol}] [${r.testId}] ${r.claim}`);
    if (!r.passed) {
      allPassed = false;
      console.log('       Details:', JSON.stringify(r, null, 2));
    }
  });

  console.log('\n------------------------------------------------------------------------');
  if (allPassed) {
    console.log(`SUCCESS: All ${results.length} PoC demonstration tests passed cleanly!`);
    console.log('All claims in Section S are cryptographically & logically verified.');
  } else {
    console.error(`FAILURE: One or more PoC tests failed.`);
    process.exit(1);
  }
  console.log('========================================================================\n');
}

run().catch(err => {
  console.error('Test execution error:', err);
  process.exit(1);
});
