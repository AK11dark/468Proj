const bonjour = require('bonjour')();

const service = bonjour.publish({
  name: 'peer1-ruby',
  type: 'p2p',
  port: 3003
});

console.log('📡 Advertising peer1-ruby._p2p._tcp.local on port 3003');
