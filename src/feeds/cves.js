const axios = require('axios');
const cache = require('../utils/cache');
const logger = require('../utils/logger');
const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CISA_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const NVD_KEY = process.env.NVD_API_KEY;
function normalizeNVD(item) {
  const cve = item.cve;
  const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
  const cvss = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore || null;
  const sevMap = s => !s ? 'medium' : s >= 9 ? 'critical' : s >= 7 ? 'high' : s >= 4 ? 'medium' : 'low';
  return { id: cve.id, source: 'NVD', title: desc.substring(0,120), description: desc, cvss: cvss ? parseFloat(cvss.toFixed(1)) : null, severity: sevMap(cvss), product: 'See NVD', versions: 'See NVD', patch: 'Check NVD', exploited: false, publishedDate: cve.published, url: `https://nvd.nist.gov/vuln/detail/${cve.id}` };
}
async function fetchRecentCVEs({ limit = 20 } = {}) {
  const cacheKey = `nvd:cves:${limit}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;
  try {
    const pubStartDate = new Date(Date.now() - 30 * 86400000).toISOString().replace(/\.\d{3}Z$/, '.000 UTC+00:00');
    const pubEndDate = new Date().toISOString().replace(/\.\d{3}Z$/, '.000 UTC+00:00');
    const hdrs = NVD_KEY && !NVD_KEY.startsWith('your_') ? { apiKey: NVD_KEY } : {};
    const res = await axios.get(NVD_BASE, { headers: hdrs, params: { pubStartDate, pubEndDate, cvssV3Severity: 'CRITICAL', resultsPerPage: Math.min(limit, 2000) }, timeout: 15000 });
    let cves = (res.data.vulnerabilities || []).map(normalizeNVD);
    try { const kev = await fetchCISAKEV(); const ids = new Set(kev.map(k => k.cveID)); cves = cves.map(c => ({ ...c, exploited: ids.has(c.id) })); } catch(_) {}
    cache.set(cacheKey, cves, cache.TTL.MEDIUM);
    return cves;
  } catch(err) { logger.error('NVD failed', {error:err.message}); return getMockCVEs(); }
}
async function fetchCISAKEV() {
  const cached = cache.get('cisa:kev');
  if (cached) return cached;
  const res = await axios.get(CISA_URL, { timeout: 10000 });
  const vulns = (res.data.vulnerabilities || []).slice(0, 100);
  cache.set('cisa:kev', vulns, cache.TTL.LONG);
  return vulns;
}
async function fetchRecentKEV({ limit = 10 } = {}) {
  const all = await fetchCISAKEV();
  return all.sort((a,b) => new Date(b.dateAdded) - new Date(a.dateAdded)).slice(0,limit).map(v => ({ id: v.cveID, source: 'CISA KEV', title: v.vulnerabilityName, description: v.shortDescription, cvss: null, severity: 'critical', product: v.product, versions: 'see advisory', patch: v.requiredAction || 'Apply patch', exploited: true, publishedDate: v.dateAdded, url: `https://nvd.nist.gov/vuln/detail/${v.cveID}` }));
}
function getMockCVEs() { return [{ id:'CVE-2024-50891', source:'NVD', title:'Apache Tomcat RCE', description:'Critical RCE in Apache Tomcat.', cvss:9.8, severity:'critical', product:'Apache Tomcat', versions:'< 9.0.98', patch:'Available', exploited:true, publishedDate: new Date().toISOString(), url:'linkX' }]; }
module.exports = { fetchRecentCVEs, fetchCISAKEV, fetchRecentKEV };
