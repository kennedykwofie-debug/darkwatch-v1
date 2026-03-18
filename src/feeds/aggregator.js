const otx = require('./otx');
const cves = require('./cves');
const abusech = require('./abusech');
const phishing = require('./phishing');
const actors = require('./actors');
const cache = require('../utils/cache');
const logger = require('../utils/logger');

const IND = {
  finance: ['bank','finance','financial','payment','fintech','swift'],
  healthcare: ['health','medical','hospital','pharma','patient','hipaa'],
  energy: ['energy','oil','gas','power','grid','pipeline','nuclear'],
  government: ['government','federal','military','defense','nato','dod'],
  technology: ['tech','software','cloud','aws','azure','npm','github'],
  retail: ['retail','ecommerce','shop','merchant','stripe','shopify'],
  manufacturing: ['manufactur','industrial','ics','scada','factory'],
};
const REG = {
  na: ['united states','us ','usa','canada'],
  eu: ['europe','germany','france','uk ','nato','ukraine'],
  apac: ['asia','china','japan','korea','singapore','australia'],
  mena: ['middle east','iran','saudi','uae','africa'],
  latam: ['brazil','mexico','argentina','colombia'],
};

function inferInd(text) {
  const t = text.toLowerCase();
  return Object.entries(IND).filter(([,k]) => k.some(w => t.includes(w))).map(([i]) => i);
}
function inferReg(text) {
  const t = text.toLowerCase();
  return Object.entries(REG).filter(([,k]) => k.some(w => t.includes(w))).map(([r]) => r);
}
function cvssToSev(s) {
  return !s ? 'medium' : s >= 9 ? 'critical' : s >= 7 ? 'high' : s >= 4 ? 'medium' : 'low';
}
function dedupeIoCs(iocs) {
  const seen = new Set();
  return iocs.filter(i => { if (seen.has(i.value)) return false; seen.add(i.value); return true; });
}
function cveToEvent(c) {
  const combined = c.title + ' ' + c.description;
  return {
    id: 'EVENT-' + c.id, source: c.source,
    type: c.exploited ? '0-DAY EXPLOIT' : 'CVE',
    title: c.id + ': ' + c.title, description: c.description,
    severity: c.cvss ? cvssToSev(c.cvss) : c.severity,
    industry: inferInd(combined).length ? inferInd(combined) : ['technology'],
    region: ['na','eu','apac'],
    tags: [c.id, c.product, c.exploited ? 'exploited' : 'patch'].filter(Boolean),
    createdAt: c.publishedDate, url: c.url,
  };
}
function phishToEvent(p) {
  return {
    id: 'EVENT-' + (p.id || ('PHISH-' + Math.random().toString(36).slice(2,8))),
    source: p.source, type: 'PHISHING',
    title: p.subject || ('Phishing targeting ' + p.target),
    description: 'Active ' + p.type + ' campaign targeting ' + p.target + '. ' + (p.domains || 1) + ' domain(s). Kit: ' + (p.kit || 'unknown') + '.',
    severity: 'high',
    industry: inferInd(p.target || ''),
    region: ['na','eu'],
    tags: ['phishing', p.target && p.target.toLowerCase(), p.type && p.type.toLowerCase()].filter(Boolean),
    createdAt: p.firstSeen || p.submittedAt || new Date().toISOString(),
    url: p.url || null,
  };
}

async function aggregateAll({ industry, region, severity, limit = 50 } = {}) {
  const ck = 'agg:all:' + industry + ':' + region + ':' + severity + ':' + limit;
  const cached = cache.get(ck); if (cached) return cached;
  logger.info('Aggregating feeds...');
  const [pulses, rcves, rphish, riocs] = await Promise.allSettled([
    otx.fetchPulses({ limit: 20 }),
    cves.fetchRecentCVEs({ limit: 15 }),
    phishing.fetchPhishingCampaigns(),
    aggregateIoCs(),
  ]);
  let events = [
    ...(pulses.status === 'fulfilled' ? pulses.value : []),
    ...(rcves.status === 'fulfilled' ? rcves.value.map(cveToEvent) : []),
    ...(rphish.status === 'fulfilled' ? rphish.value.slice(0,10).map(phishToEvent) : []),
  ];
  events = events.map(e => ({
    ...e,
    industry: (e.industry && e.industry.length) ? e.industry : inferInd(e.title + ' ' + e.description),
    region: (e.region && e.region.length) ? e.region : inferReg(e.title + ' ' + e.description),
  }));
  if (industry && industry !== 'all') events = events.filter(e => e.industry && e.industry.includes(industry));
  if (region && region !== 'all') events = events.filter(e => e.region && e.region.includes(region));
  if (severity && severity !== 'all') events = events.filter(e => e.severity === severity);
  const so = { critical: 0, high: 1, medium: 2, low: 3 };
  events.sort((a, b) => ((so[a.severity] || 4) - (so[b.severity] || 4)) || new Date(b.createdAt) - new Date(a.createdAt));
  const result = {
    events: events.slice(0, limit),
    iocs: riocs.status === 'fulfilled' ? riocs.value : [],
    total: events.length,
    filters: { industry, region, severity },
    fetchedAt: new Date().toISOString(),
  };
  cache.set(ck, result, cache.TTL.SHORT);
  return result;
}

async function aggregateIoCs({ limit = 100 } = {}) {
  const cached = cache.get('agg:iocs'); if (cached) return cached;
  const [otxI, abuI] = await Promise.allSettled([
    otx.fetchIndicators({ limit: 50 }),
    abusech.fetchAllAbuseIoCs(),
  ]);
  const combined = [
    ...(otxI.status === 'fulfilled' ? otxI.value : []),
    ...(abuI.status === 'fulfilled' ? abuI.value : []),
  ];
  const deduped = dedupeIoCs(combined)
    .sort((a, b) => (b.confidence || 0) - (a.confidence || 0))
    .slice(0, limit)
    .map((ioc, i) => ({ ...ioc, id: 'IOC-' + String(i + 1).padStart(4, '0'), first: fmt(ioc.firstSeen) }));
  cache.set('agg:iocs', deduped, cache.TTL.SHORT);
  return deduped;
}

async function getStats() {
  const cached = cache.get('agg:stats'); if (cached) return cached;
  const [all, iocs, al, cl, pl] = await Promise.allSettled([
    aggregateAll({ limit: 200 }),
    aggregateIoCs({ limit: 500 }),
    actors.fetchThreatActors({ limit: 50 }),
    cves.fetchRecentCVEs({ limit: 50 }),
    phishing.fetchPhishingCampaigns(),
  ]);
  const ev = all.status === 'fulfilled' ? all.value.events : [];
  const stats = {
    criticalThreats: ev.filter(e => e.severity === 'critical').length,
    activeIoCs: (iocs.status === 'fulfilled' ? iocs.value : []).length,
    threatActors: al.status === 'fulfilled' ? al.value.length : 0,
    zeroDayCVEs: (cl.status === 'fulfilled' ? cl.value : []).filter(c => c.exploited).length,
    phishingKits: (pl.status === 'fulfilled' ? pl.value : []).length,
    totalEvents: ev.length,
    lastUpdated: new Date().toISOString(),
    sourceStatus: {
      otx: KEY(process.env.OTX_API_KEY),
      nvd: KEY(process.env.NVD_API_KEY),
      phishtank: KEY(process.env.PHISHTANK_API_KEY),
      urlhaus: 'active', bazaar: 'active', feodo: 'active',
      threatfox: 'active', mitre: 'active', cisa: 'active',
    },
  };
  cache.set('agg:stats', stats, cache.TTL.SHORT);
  return stats;
}

function KEY(k) { return k && !k.startsWith('your_') ? 'active' : 'no-key'; }
function fmt(iso) {
  if (!iso) return 'unknown';
  const d = Date.now() - new Date(iso).getTime();
  const m = Math.floor(d / 60000), h = Math.floor(d / 3600000), dy = Math.floor(d / 86400000);
  return m < 60 ? m + 'm ago' : h < 24 ? h + 'h ago' : dy + 'd ago';
}

module.exports = {
  aggregateAll, aggregateIoCs, getStats,
  fetchThreatActors: actors.fetchThreatActors,
  fetchRecentCVEs: cves.fetchRecentCVEs,
  fetchRecentKEV: cves.fetchRecentKEV,
  fetchPhishing: phishing.fetchPhishingCampaigns,
};
