function assertLiveCheckPort(port) {
  if (!port || typeof port.run !== 'function') throw new TypeError('Live check port must expose run(url, analysis).');
  return port;
}

module.exports = { assertLiveCheckPort };
