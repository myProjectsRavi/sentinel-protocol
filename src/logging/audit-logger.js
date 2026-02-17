const fs = require('fs');
const path = require('path');

class AuditLogger {
  constructor(filePath) {
    this.filePath = filePath;
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  write(event) {
    const line = `${JSON.stringify(event)}\n`;
    fs.appendFile(this.filePath, line, () => {});
  }
}

module.exports = {
  AuditLogger,
};
