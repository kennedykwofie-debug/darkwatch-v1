const axios = require('axios');
const cache = require('../utils/cache');
const logger = require('../utils/logger');

const BASE = 'https://otx.alienvault.com/api/v1';
const KEY  = process.env.OTX_API_KEY;
const headers = () => ({ 'X-OTX-API-KEY': KEY });

function normalizePulse(pulse) {
  const sevMap = tlp => tlp === 'red' ? 'critical' : tlp === 'amber' ? 'high' : tlp === 'green' ? 'medium' : 'low';
  return {
    id: 'OTX-' + pulse.id, source: 'AlienVault OTX',
    type: (pulse.tags && pulse.tags[0] && pulse.tags[0].toUpperCase()) || 'THREAT INTEL',
    title: pulse.name, description: pulse.description || 'No description.',
    severity: sevMap(pulse.tlp),
    industry: (pulse.industries || []).map(i => i.toLowerCase()),
    region: (pulse.targeted_countries || []).map(r => r.toLowerCase()),
    tags: pulse.tags || [],
    iocs: (pulse.indicators || []).slice(0, 20).map(ind => ({ type: ind.type, value: ind.indicator, confidence: 75, source: 'OTX', firstSeen: ind.created })),
    createdAt: pulse.created, url: 'https://otx.alienvault.com/pulse/' + pulse.id,
  };
}

async function fetchPulses({ limit = 20 } = {}) {
  const cacheKey = 'otx:pulses:' + limit;
  const cached = cache.get(cacheKey); if (cached) return cached;
  if (!KEY || KEY === 'your_otx_api_key_here') { logger.warn('OTX: no key - mock data'); return getMockPulses(); }
  try {
    const since = new Date(Date.now() - 7 * 86400000).toISOString();
    const res = await axios.get(BASE + '/pulses/subscribed', { headers: headers(), params: { limit, modified_since: since }, timeout: 10000 });
    const pulses = (res.data.results || []).map(normalizePulse);
    cache.set(cacheKey, pulses, cache.TTL.SHORT);
    logger.info('OTX: fetched ' + pulses.length + ' pulses');
    return pulses;
  } catch (err) {
    logger.error('OTX pulses failed', { error: err.message });
    return getMockPulses();
  }
}

async function fetchIndicators({ type = 'IPv4', limit = 50 } = {}) {
  const cacheKey = 'otx:indicators:' + type + ':' + limit;
  const cached = cache.get(cacheKey); if (cached) return cached;
  if (!KEY || KEY === 'your_otx_api_key_here') return getMockIoCs();
  try {
    const res = await axios.get(BASE + '/indicators/export', { headers: headers(), params: { type, limit }, timeout: 10000 });
    const indicators = (res.data.results || []).map(ind => ({ type: ind.type, value: ind.indicator, confidence: 75, source: 'OTX', firstSeen: ind.created, tags: ind.tags || [] }));
    cache.set(cacheKey, indicators, cache.TTL.SHORT);
    return indicators;
  } catch (err) {
    logger.error('OTX indicators failed', { error: err.message });
    return getMockIoCs();
  }
}

function getMockPulses() {
  return [
    { id:'OTX-MOCK-001', source:'AlienVault OTX', type:'RANSOMWARE', title:'LockBit 3.0 Campaign Targeting APAC Finance', description:'Active LockBit 3.0 ransomware campaign targeting financial institutions across Singapore, Hong Kong, and Tokyo via spear-phishing.', severity:'critical', industry:['finance'], region:['apac'], tags:['lockbit','ransomware','apac'], iocs:[], createdAt: new Date().toISOString(), url:'https://otx.alienvault.com' },
    { id:'OTX-MOCK-002', source:'AlienVault OTX', type:'APT', title:'APT41 Infrastructure Reactivation', description:'Chinese state-sponsored group APT41 spinning up new C2 infrastructure targeting energy sector in EU and NA.', severity:'critical', industry:['energy'], region:['eu','na'], tags:['apt41','china','c2'], iocs:[], createdAt: new Date().toISOString(), url:'https://otx.alienvault.com' },
    { id:'OTX-MOCK-003', source:'AlienVault OTX', type:'INFOSTEALER', title:'RedLine Stealer via Malicious npm Packages', description:'Updated RedLine variant with improved AV evasion found in npm supply chain. Targeting developer machines.', severity:'high', industry:['technology'], region:['na','eu'], tags:['redline','npm','supply-chain'], iocs:[], createdAt: new Date().toISOString(), url:'https://otx.alienvault.com' },
  ];
}
function getMockIoCs() {
  return [
    { type:'IPv4', value:'185.220.101.47', confidence:95, source:'OTX', firstSeen: new Date().toISOString(), tags:['c2','tor-exit'] },
    { type:'domain', value:'apt41-update.ddns.net', confidence:96, source:'OTX', firstSeen: new Date().toISOString(), tags:['apt41','c2'] },
  ];
}

module.exports = { fetchPulses, fetchIndicators };
