function writeAudit(server, payload) {
  server.auditLogger.write(payload);
}

function writeAuditAndStatus(server, payload) {
  writeAudit(server, payload);
  server.writeStatus();
}

module.exports = {
  writeAudit,
  writeAuditAndStatus,
};
