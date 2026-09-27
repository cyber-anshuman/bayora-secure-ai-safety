const DedicatedInferenceWorker = require('../src/model/inference_worker');
const assert = require('assert');

function runWeightIntegrityUnitTest() {
  console.log('Running Weight Integrity Unit Tests (Issue 1)...');

  // Test 1: Happy path - matching hash initializes cleanly
  const cleanWorker = new DedicatedInferenceWorker('worker-happy-unit');
  cleanWorker.create('sess-happy-1');
  const initResult = cleanWorker.initialize();
  assert.strictEqual(cleanWorker.status, 'INITIALIZED', 'Clean worker status must be INITIALIZED');
  assert.strictEqual(initResult.weightsHash, cleanWorker.pinnedWeightsHash, 'Weights hash must match pinned hash');
  console.log('✓ Happy path passed: matching hash initialized successfully.');

  // Test 2: Mismatched loadedWeightsId throws HARNESS_ERROR_CONFIG_DRIFT
  const driftedWorker = new DedicatedInferenceWorker('worker-drifted-unit', 'tampered_weights_identifier_drift_999');
  driftedWorker.create('sess-drift-1');
  let errorThrown = null;
  try {
    driftedWorker.initialize();
  } catch (err) {
    errorThrown = err;
  }

  assert(errorThrown !== null, 'initialize() must throw on mismatched loadedWeightsId');
  assert.strictEqual(driftedWorker.status, 'HARNESS_ERROR_CONFIG_DRIFT', 'Worker status must be HARNESS_ERROR_CONFIG_DRIFT');
  assert.strictEqual(errorThrown.code, 'HARNESS_ERROR_CONFIG_DRIFT', 'Error code must be HARNESS_ERROR_CONFIG_DRIFT');
  assert(errorThrown.message.includes('HARNESS_ERROR_CONFIG_DRIFT'), 'Error message must include HARNESS_ERROR_CONFIG_DRIFT');
  console.log('✓ Drift detection passed: mismatched loadedWeightsId threw HARNESS_ERROR_CONFIG_DRIFT and set status.');

  // Test 3: Explicit matching loadedWeightsId (matching pinned hash)
  const explicitCleanWorker = new DedicatedInferenceWorker('worker-explicit-clean', cleanWorker.pinnedWeightsHash);
  explicitCleanWorker.create('sess-happy-2');
  const explicitInit = explicitCleanWorker.initialize();
  assert.strictEqual(explicitCleanWorker.status, 'INITIALIZED');
  assert.strictEqual(explicitInit.weightsHash, explicitCleanWorker.pinnedWeightsHash);
  console.log('✓ Explicit matching loadedWeightsId passed.');

  console.log('\nAll weight integrity unit tests passed cleanly!');
}

runWeightIntegrityUnitTest();
