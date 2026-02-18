const path = require('path');
const os = require('os');
const { Worker } = require('worker_threads');

function positiveIntOr(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
}

class ScanWorkerPool {
  constructor(config = {}) {
    this.enabled = config.enabled !== false;
    this.size = positiveIntOr(config.size, Math.max(1, Math.min(4, (os.cpus()?.length || 2) - 1)));
    this.queueLimit = positiveIntOr(config.queue_limit, 1024);
    this.taskTimeoutMs = positiveIntOr(config.task_timeout_ms, 10000);
    this.scanTaskTimeoutMs = positiveIntOr(config.scan_task_timeout_ms, Math.min(this.taskTimeoutMs, 2000));
    this.embedTaskTimeoutMs = positiveIntOr(config.embed_task_timeout_ms, Math.max(this.taskTimeoutMs, 10000));

    this.workers = [];
    this.pending = new Map();
    this.nextTaskId = 1;
    this.queueDepth = 0;
    this.closing = false;

    if (!this.enabled) {
      return;
    }

    try {
      for (let i = 0; i < this.size; i += 1) {
        this.workers.push(this.createWorkerInfo(i));
      }
    } catch {
      this.enabled = false;
      this.workers = [];
      this.pending.clear();
    }
  }

  createWorkerInfo(index) {
    const workerPath = path.join(__dirname, 'scan-worker.js');
    const worker = new Worker(workerPath);
    const info = {
      index,
      worker,
      inflight: 0,
      alive: true,
    };

    worker.on('message', (message) => {
      this.onWorkerMessage(info, message);
    });
    worker.on('error', (error) => {
      this.onWorkerFailure(info, error);
    });
    worker.on('exit', (code) => {
      if (this.closing) {
        return;
      }
      this.onWorkerFailure(info, new Error(`scan worker exited with code ${code}`));
      if (this.enabled) {
        const replacement = this.createWorkerInfo(index);
        this.workers[index] = replacement;
      }
    });

    return info;
  }

  onWorkerMessage(info, message) {
    const pending = this.pending.get(message?.id);
    if (!pending) {
      return;
    }
    this.pending.delete(message.id);
    clearTimeout(pending.timeout);
    pending.info.inflight = Math.max(0, pending.info.inflight - 1);
    this.queueDepth = Math.max(0, this.queueDepth - 1);

    if (message.ok) {
      pending.resolve(message.result);
      return;
    }
    pending.reject(new Error(message.error || 'scan worker task failed'));
  }

  rejectPendingForWorker(info, error) {
    for (const [taskId, pending] of this.pending.entries()) {
      if (pending.info !== info) {
        continue;
      }
      clearTimeout(pending.timeout);
      this.pending.delete(taskId);
      pending.info.inflight = Math.max(0, pending.info.inflight - 1);
      this.queueDepth = Math.max(0, this.queueDepth - 1);
      pending.reject(error);
    }
  }

  onWorkerFailure(info, error) {
    info.alive = false;
    this.rejectPendingForWorker(info, error);
  }

  selectWorker() {
    const alive = this.workers.filter((entry) => entry.alive);
    if (alive.length === 0) {
      return null;
    }
    alive.sort((a, b) => a.inflight - b.inflight || a.index - b.index);
    return alive[0];
  }

  async scan(payload) {
    return this.dispatchTask('scan', payload);
  }

  async embed(payload) {
    return this.dispatchTask('embed', payload);
  }

  async dispatchTask(kind, payload) {
    if (!this.enabled) {
      throw new Error('scan worker pool disabled');
    }
    if (this.queueDepth >= this.queueLimit) {
      throw new Error('scan worker queue limit exceeded');
    }

    const info = this.selectWorker();
    if (!info) {
      throw new Error('no scan workers available');
    }

    const timeoutMs = kind === 'embed' ? this.embedTaskTimeoutMs : this.scanTaskTimeoutMs;

    const taskId = this.nextTaskId++;
    this.queueDepth += 1;
    info.inflight += 1;

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pending.delete(taskId);
        info.inflight = Math.max(0, info.inflight - 1);
        this.queueDepth = Math.max(0, this.queueDepth - 1);
        reject(new Error(`scan worker timeout after ${timeoutMs}ms`));
      }, timeoutMs);
      timeout.unref?.();

      this.pending.set(taskId, {
        resolve,
        reject,
        timeout,
        info,
      });
      info.worker.postMessage({
        id: taskId,
        kind,
        payload,
      });
    });
  }

  async close() {
    this.closing = true;
    this.enabled = false;
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timeout);
      pending.reject(new Error('scan worker pool shutting down'));
    }
    this.pending.clear();
    this.queueDepth = 0;

    await Promise.allSettled(
      this.workers.map((entry) => {
        if (!entry.worker) {
          return Promise.resolve();
        }
        return entry.worker.terminate();
      })
    );
    this.workers = [];
  }
}

module.exports = {
  ScanWorkerPool,
};
