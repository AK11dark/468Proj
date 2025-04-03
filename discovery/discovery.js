const bonjour = require('bonjour')();
const fs = require('fs');

const results = [];

console.log("🔍 Discovering _p2p._tcp services...");

const browser = bonjour.find({ type: 'p2p' }, service => {
  const peer = {
    name: service.name,
    host: service.referer.address,
    port: service.port
  };
  console.log(`➡️ Found: ${peer.name} @ ${peer.host}:${peer.port}`);
  results.push(peer);
});

// Save to peers.json after 3 seconds
setTimeout(() => {
fs.writeFileSync('../peer1_logan/peers.json', JSON.stringify(results, null, 2));
  console.log("✅ Wrote peers to peers.json");
  process.exit();
}, 3000);
