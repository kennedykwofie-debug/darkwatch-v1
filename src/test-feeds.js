require('dotenv').config();
const abusech = require('./feeds/abusech');
const cves = require('./feeds/cves');
const actors = require('./feeds/actors');
const phishing = require('./feeds/phishing');
const otx = require('./feeds/otx');
async function test(name, fn) {
  process.stdout.write(`  Testing ${name.padEnd(28)} `);
  try { const r = await fn(); console.log(`\u2713  ${Array.isArray(r) ? r.length : Object.keys(r).length} items`); }
  catch(err) { console.log(`\u2717  FAILED: ${err.message}`); }
}
(async () => {
  console.log('\nDARKWATCH Feed Test\n');
  await test('URLhaus',  () => abusech.fetchURLhaus({limit:5}));
  await test('MalwareBazaar',() => abusech.fetchMalwareBazaar({limit:5}));
  await test('Feodo Tracker',() => abusech.fetchFeodoTracker());
  await test('ThreatFox',  () => abusech.fetchThreatFox({days:1,limit:5}));
  await test('CISA KEV',   () => cves.fetchCISAKEV());
  await test('MITRE AIT&CI€’("†=> actors.fetchThreatActors({limit:5}));
  await test('OpenPhish',  () => phishing.fetchOpenPhish({limit:5}));
  await test('AlienVault OTX',() => otx.fetchPulses({limit:3}));
  await test('NVD CVEs',   () => cves.fetchRecentCVEs({limit:3}));
  console.log('\nDone. npm start to launch.\n');
})();