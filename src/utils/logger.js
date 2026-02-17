function log(level, message, context = {}) {
  const event = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...context,
  };

  const line = JSON.stringify(event);
  if (level === 'error' || level === 'warn') {
    console.error(line);
    return;
  }
  console.log(line);
}

module.exports = {
  info: (message, context) => log('info', message, context),
  warn: (message, context) => log('warn', message, context),
  error: (message, context) => log('error', message, context),
};
