/**
 * Bayora Isolated Tenant Worker Execution Thread
 * Runs inside a dedicated worker_thread V8 isolate.
 *
 * Enforces per-tenant memory isolation, private secret state, and nested vm.Context execution.
 */

const { parentPort, workerData } = require('worker_threads');
const crypto = require('crypto');
const vm = require('vm');

// Private module-scoped secret unique to this worker isolate instance.
// Never exposed on global, never sent back in raw plaintext.
const LOCAL_SECRET = crypto.randomBytes(16).toString('hex');

function sha256(data) {
  return crypto.createHash('sha256').update(String(data || '')).digest('hex');
}

async function handleTask() {
  if (!workerData || !workerData.task) {
    throw new Error('WorkerData missing task specification');
  }

  const task = workerData.task;

  switch (task.type) {
    case 'DIGEST': {
      const payloadText = task.payloadText ?? '';
      const digest = sha256(payloadText);
      return { digest };
    }

    case 'KEYWORD_SCAN': {
      const text = (task.text || '').toLowerCase();
      const keywords = Array.isArray(task.keywords) ? task.keywords : [];

      // Nested vm context execution with 250ms timeout
      const sandbox = {
        text,
        keywords,
        flagged: false
      };
      const context = vm.createContext(sandbox);
      const code = `
        for (const kw of keywords) {
          if (text.includes(kw.toLowerCase())) {
            flagged = true;
            break;
          }
        }
      `;
      vm.runInContext(code, context, { timeout: 250 });
      return { flagged: sandbox.flagged };
    }

    case 'PROBE_FOREIGN_SECRET': {
      return {
        globalLeak: typeof global.__TENANT_SECRET__ !== 'undefined' ? global.__TENANT_SECRET__ : null,
        ownSecretFingerprint: sha256(LOCAL_SECRET)
      };
    }

    case 'ALLOCATE_OVERSIZED': {
      // Deliberately push millions of small live objects to breach V8's maxOldGenerationSizeMb
      const megabytes = Number(task.megabytes) || 64;
      const count = megabytes * 12000;
      const retainedHeap = [];
      for (let i = 0; i < count; i++) {
        retainedHeap.push({
          i,
          marker: 'allocated_small_retained_heap_object',
          pad: 'y'.repeat(100)
        });
      }
      return { allocatedCount: retainedHeap.length };
    }

    case 'ASYNC_PING': {
      return Promise.resolve({ pong: true, tenant: workerData.tenantId });
    }

    case 'ASYNC_FAIL': {
      return Promise.reject(new Error('Deliberate async worker failure'));
    }

    default:
      throw new Error(`Unknown task type: ${task.type}`);
  }
}

if (parentPort) {
  try {
    const result = handleTask();
    if (result && typeof result.then === 'function') {
      result
        .then(res => parentPort.postMessage({ ok: true, result: res }))
        .catch(err => parentPort.postMessage({ ok: false, error: err.message }));
    } else {
      parentPort.postMessage({ ok: true, result });
    }
  } catch (err) {
    parentPort.postMessage({ ok: false, error: err.message });
  }
}
