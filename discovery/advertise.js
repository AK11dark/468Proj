const bonjour = require('bonjour')();

const service = bonjour.publish({
  name: 'peer1-ruby',
  type: 'peer',
  port: 3002
});

console.log('📡 Advertising peer1-ruby._p2p._tcp.local on port 3002');
