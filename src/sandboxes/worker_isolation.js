/**
 * Bayora Worker Threads Runtime Isolation Layer
 *
 * SCOPE AND BOUNDARIES:
 * What this DOES provide:
 * 1. Separate V8 Isolate & Heap: Each worker thread executes in its own distinct V8
 *    isolate with private call stacks, private memory heaps, and isolated global contexts.
 * 2. No Shared Object Graph: Messages between the host and worker pass via structured
 *    clone serialization. No shared object references exist, and SharedArrayBuffer is
 *    NOT used anywhere in the codebase.
 * 3. Enforced Resource Limits: V8 actively enforces `maxOldGenerationSizeMb`,
 *    `maxYoungGenerationSizeMb`, `codeRangeSizeMb`, and `stackSizeMb`. An allocation
 *    exceeding old generation limits triggers an immediate isolate termination (OOM kill).
 *
 * What this DOES NOT provide (Crucial Architecture Distinction):
 * 1. NO Separate Kernel: All worker threads share the same host operating system kernel.
 * 2. NO Filesystem / Rootfs Isolation: Workers can still access the filesystem unless
 *    strictly bounded (unlike Kata microVM read-only rootfs).
 * 3. NO Syscall Filtering: Workers can invoke arbitrary system calls permitted to the
 *    Node.js host process (unlike Kata seccomp/capabilities drop).
 * 4. NO Network Namespace Isolation: Workers share the host networking stack (unlike
 *    Cilium eBPF container network interfaces).
 *
 * This layer represents partial runtime memory isolation at the JavaScript engine tier,
 * and must NOT be equated with hypervisor or hardware container isolation (Kata).
 */

const { Worker } = require('worker_threads');
const path = require('path');

const DEFAULT_RESOURCE_LIMITS = {
  maxOldGenerationSizeMb: 64,
  maxYoungGenerationSizeMb: 16,
  codeRangeSizeMb: 16,
  stackSizeMb: 4
};

const WORKER_SCRIPT_PATH = path.join(__dirname, 'workers', 'tenant_worker.js');

/**
 * Spawns a dedicated, single-use V8 worker_thread to execute a sandboxed tenant task.
 *
 * @param {string} tenantId - 'red' | 'blue' | 'model'
 * @param {object} task - Task payload ({ type: string, ... })
 * @param {object} [resourceLimits] - V8 memory resource limits
 * @param {number} [timeoutMs] - Execution timeout in ms (default: 5000)
 * @returns {Promise<any>} Resolves with the worker task result
 */
function runInIsolatedWorker(tenantId, task, resourceLimits = DEFAULT_RESOURCE_LIMITS, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const mergedLimits = {
      ...DEFAULT_RESOURCE_LIMITS,
      ...(resourceLimits || {})
    };

    let worker = null;
    let timer = null;
    let settled = false;

    const cleanup = () => {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      if (worker) {
        worker.terminate().catch(() => {});
        worker = null;
      }
    };

    const settleResolve = (value) => {
      if (!settled) {
        settled = true;
        cleanup();
        resolve(value);
      }
    };

    const settleReject = (err) => {
      if (!settled) {
        settled = true;
        cleanup();
        reject(err);
      }
    };

    timer = setTimeout(() => {
      settleReject(new Error(`Worker execution timed out after ${timeoutMs}ms (tenant: ${tenantId}, task: ${task?.type})`));
    }, timeoutMs);

    try {
      worker = new Worker(WORKER_SCRIPT_PATH, {
        workerData: {
          tenantId,
          task
        },
        resourceLimits: mergedLimits
      });

      worker.on('message', (msg) => {
        if (!msg) {
          settleReject(new Error('Received empty message from worker'));
          return;
        }
        if (msg.ok) {
          // Expose result directly while keeping compatibility with any wrapper expectations
          const res = msg.result;
          if (res && typeof res === 'object') {
            res.ok = true;
          }
          settleResolve(res);
        } else {
          settleReject(new Error(msg.error || 'Worker execution error'));
        }
      });

      worker.on('error', (err) => {
        settleReject(err);
      });

      worker.on('exit', (code) => {
        if (code !== 0) {
          settleReject(
            new Error(
              `Worker exited with non-zero exit code ${code} (likely caused by V8 resourceLimits enforcement, e.g. JS heap old-generation OOM kill)`
            )
          );
        }
      });
    } catch (err) {
      settleReject(err);
    }
  });
}

module.exports = {
  runInIsolatedWorker,
  DEFAULT_RESOURCE_LIMITS
};
