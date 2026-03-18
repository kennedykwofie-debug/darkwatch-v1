/**
 * abuse.ch Feeds — URLhaus, MalwareBazaar, Feodo Tracker, ThreatFox
 * All public, no key required
 */
const axios = require('axios');
const cache = require('../utils/cache');
const logger = require('../utils/logger');
const URLHAUS_API = 'https://urlhaus-api.abuse.ch/v1';
const BAZAAR_API = 'https://mb-api.abuse.ch/api/v1';
const FEODO_URL = 'https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.json';
const THREATFOX_API = 'https://threatfox-api.abuse.ch/api/v1';
async function fetchURLhaus({ limit = 20 } = {}) {
  const cached = cache.get('urlhaus:recent'); if (cached) return cached;
  try {
    const res = await axios.post(`${URLHAUS_API}/urls/recent/`, null, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000 });
    const urls = (res.data.urls || []).slice(0,limit).map(u => ({ type:'URL', value:u.url, confidence:u.url_status === 'online' ? 95 : 75, source:'URLhaus', firstSeen:u.date_added, tags:(u.tags || []), status:u.url_status }));
    cache.set('urlhaus:recent', urls, cache.TTL.SHORT); logger.info(`URLhaus: ${urls.length} URLs`); return urls;
  } catch(err) { logger.error('URLhaus failed',err.message); return []; }
}
async function fetchMalwareBazaar({ limit = 20 } = {}) {
  const cached = cache.get('bazaar:recent'); if (cached) return cached;
  try {
    const res = await axios.post(BAZAAR_API, 'query=get_recent&selector=100', { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000 });
    const s = (res.data.data || []).slice(0,limit).map(x => ({ type:'SHA256', value:x.sha256_hash, confidence:90, source:'MalwareBazaar', firstSeen:x.first_seen, tags:x.tags || [], malwareFamily:x.signature || 'unknown' }));
    cache.set('bazaar:recent',s,cache.TTL.SHORT); return s;
  } catch(err) { logger.error('Bazaar failed',err.message); return []; }
}
async function fetchFeodoTracker() {
  const cached = cache.get('feodo:c2ips'); if (cached) return cached;
  try {
    const res = await axios.get(FEODO_URL, { timeout: 10000 });
    const ips = (res.data || []).slice(0,50).map(e => ({ type:'IPv4', value:e.ip_address, confidence:95, source:'Feodo Tracker', firstSeen:e.first_seen, tags:[e.malware,'c2','botnet'].filter(Boolean), malware:e.malware, country:e.country }));
    cache.set('feodo:c2ips',
    ips,cache.TTL.SHORT); return ips;
  } catch(err) { logger.error('Feodo failed',err.message); return []; }
}
async function fetchThreatFox({ days = 1, limit = 30 } = {}) {
  const cached = cache.get(`threatfox:joocs:${days}`); if (cached) return cached;
  try {
    const res = await axios.post(THREATFOX_API, JSON.stringify({ query: 'get_iocs', days }), { headers: { 'Content-Type': 'application/json' }, timeout: 10000 });
    if (res.data.query_status !== 'ok') return [];
    const iocs = (res.data.data || []).slice(0,limit).map(i => ({ type:i.ioc_type, value:i.ioc, confidence:i.confidence_level, source:'ThreatFox', firstSeen:i.first_seen, tags:i.tags || [], malwareFamily:i.malware }));
    cache.set(`threatfox:joocs:${days}`,iocs,cache.TTL.SHORT); return iocs;
  } catch(err) { logger.error('ThreatFox failed',err.message); return []; }
}
async function fetchAllAbuseIoCs() {
  const [urls,hashes,ips,tfox] = await Promise.allSettled([fetchURLhaus(),fetchMalwareBazaar(),fetchFeodoTracker(),fetchThreatFox()]);
  return [...(urls.status==='fulfilled'?urls.value:[]),...(hashes.status==='fulfilled'?hashes.value:[]),...(ips.status==='fulfilled'?ips.value:[]),...(tfox.status==='fulfilled'?tfox.value:[])];
}
module.exports = { fetchURLhaus, fetchMalwareBazaar, fetchFeodoTracker, fetchThreatFox, fetchAllAbuseIoCs };