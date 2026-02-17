const fs = require('fs');
const path = require('path');

class StatusStore {
  constructor(filePath) {
    this.filePath = filePath;
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  write(status) {
    fs.writeFileSync(this.filePath, JSON.stringify(status, null, 2), 'utf8');
  }

  read() {
    if (!fs.existsSync(this.filePath)) {
      return null;
    }
    return JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
  }
}

module.exports = {
  StatusStore,
};
