const fs = require('fs');
const path = require('path');

function appendFileAsync(filePath, content) {
  return new Promise((resolve, reject) => {
    fs.appendFile(filePath, content, (error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

class AuditLogger {
  constructor(filePath, options = {}) {
    this.filePath = filePath;
    this.mirrorStdout = options.mirrorStdout === true;
    this.tail = Promise.resolve();
    this.pendingCount = 0;
    this.lastError = null;
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
    if (this.mirrorStdout) {
      try {
        process.stdout.write(line);
      } catch {
        // Never break request flow due to stdout mirror failures.
      }
    }
    this.pendingCount += 1;

    const pending = this.tail.then(() => appendFileAsync(this.filePath, line));
    this.tail = pending
      .catch((error) => {
        this.lastError = error;
      })
      .finally(() => {
        this.pendingCount = Math.max(0, this.pendingCount - 1);
      });

    return pending;
  }

  async flush(options = {}) {
    const timeoutMs = Number(options.timeoutMs ?? 5000);
    const timeout = new Promise((_, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Timed out waiting for ${this.pendingCount} pending audit writes`));
      }, timeoutMs);
      timer.unref?.();
    });

    await Promise.race([
      this.tail,
      timeout,
    ]);

    if (this.lastError) {
      const error = this.lastError;
      this.lastError = null;
      throw error;
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
