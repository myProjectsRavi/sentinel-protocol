const fs = require('fs');
const path = require('path');

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

class AuditLogger {
  constructor(filePath) {
    this.filePath = filePath;
    this.pendingWrites = new Set();
    this.closed = false;
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  write(event) {
    if (this.closed) {
      return Promise.resolve();
    }

    const line = `${JSON.stringify(event)}\n`;
    const pending = new Promise((resolve, reject) => {
      fs.appendFile(this.filePath, line, (error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });

    this.pendingWrites.add(pending);
    pending.finally(() => {
      this.pendingWrites.delete(pending);
    }).catch(() => {});
    return pending;
  }

  async flush(options = {}) {
    const timeoutMs = Number(options.timeoutMs ?? 5000);
    const startedAt = Date.now();

    while (this.pendingWrites.size > 0) {
      const elapsed = Date.now() - startedAt;
      if (elapsed >= timeoutMs) {
        throw new Error(`Timed out waiting for ${this.pendingWrites.size} pending audit writes`);
      }

      await Promise.race([
        Promise.allSettled(Array.from(this.pendingWrites)),
        sleep(25),
      ]);
    }
  }

  async close(options = {}) {
    this.closed = true;
    await this.flush(options);
  }
}

module.exports = {
  AuditLogger,
};
