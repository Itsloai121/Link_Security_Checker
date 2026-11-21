const { start } = require('./src/bootstrap/main');
try { start(); }
catch (error) {
  const timestamp = new Date().toISOString().slice(11, 19) + 'Z';
  if (process.env.NODE_ENV === 'production') console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'fatal', event: 'startup_failed', error_name: error.name }));
  else console.error(`[${timestamp}] FATAL startup failed  error=${error.name}  message=${error.message}`);
  process.exitCode = 1;
}