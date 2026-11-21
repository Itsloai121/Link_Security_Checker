function createLogger({ environment = 'development' } = {}) {
  function write(level, event, fields = {}) {
    const timestamp = new Date().toISOString();
    if (environment === 'production') {
      const line = JSON.stringify({ timestamp, level, service: 'link-safety-api', environment, event, ...fields });
      if (level === 'error') console.error(line); else console.log(line);
      return;
    }
    const time = timestamp.slice(11, 19) + 'Z';
    const label = level.toUpperCase().padEnd(5);
    const message = event.replace(/_/g, ' ');
    const context = Object.entries(fields).map(([key, value]) => `${key}=${String(value)}`).join('  ');
    const line = `[${time}] ${label} ${message}${context ? `  ${context}` : ''}`;
    if (level === 'error') console.error(line); else console.log(line);
  }
  return Object.freeze({ info: (event, fields) => write('info', event, fields), warn: (event, fields) => write('warn', event, fields), error: (event, fields) => write('error', event, fields) });
}
module.exports = { createLogger };