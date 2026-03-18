const axios = require('axios');
const cache = require('../utils/cache');
const logger = require('../utils/logger');

const OPENPHISH_URL = 'https://openphish.com/feed.txt';
const PT_KEY = process.env.PHISHTANK_API_KEY;

function extractBrand(url) {
  const brands = ['PayPal','Microsoft','Apple','Google','Amazon','Facebook','Netflix','Chase','DHL','Instagram','Binance','Coinbase','DocuSign','Dropbox','Adobe'];
  const u = url.toLowerCase();
  return brands.find(b => u.includes(b.toLowerCase())) || 'Unknown';
}

async function fetchPhishTank({ limit = 30 } = {}) {
  try {
    const res = await axios.get('https://data.phishtank.com/data/online-valid.json', {
      timeout: 15000,
      headers: { 'User-Agent': 'darkwatch/1.0' }
    });
    const entries = (Array.isArray(res.data) ? res.data : []).slice(0, limit);
    return entries.map(p => ({
      id: 'PT-' + p.phish_id,
      source: 'PhishTank',
      url: p.url,
      target: p.target || extractBrand(p.url),
      verified: p.verified === 'yes',
      online: p.online === 'yes',
      submittedAt: p.submission_time,
      type: 'Credential Harvest',
      confidence: p.verified === 'yes' ? 98 : 80,
    }));
  } catch (err) {
    return fetchOpenPhish({ limit });
  }
}

async function fetchOpenPhish({ limit = 30 } = {}) {
  const cached = cache.get('openphish:recent');
  if (cached) return cached;
  try {
    const res = await axios.get(OPENPHISH_URL, { timeout: 10000 });
    const urls = res.data.trim().split('\n').filter(Boolean).slice(0, limit);
    const phishList = urls.map((url, i) => ({
      id: 'OP-' + (i + 1),
      source: 'OpenPhish',
      url,
      target: extractBrand(url),
      verified: true,
      online: true,
      submittedAt: new Date().toISOString(),
      type: 'Credential Harvest',
      confidence: 85,
    }));
    cache.set('openphish:recent', phishList, cache.TTL.SHORT);
    logger.info('OpenPhish: fetched ' + phishList.length + ' URLs');
    return phishList;
  } catch (err) {
    logger.error('OpenPhish failed', { error: err.message });
    return getMockPhishing();
  }
}

async function fetchPhishingCampaigns() {
  const [pt, op] = await Promise.allSettled([fetchPhishTank(), fetchOpenPhish()]);
  const raw = [
    ...(pt.status === 'fulfilled' ? pt.value : []),
    ...(op.status === 'fulfilled' ? op.value : []),
  ];
  const byBrand = {};
  raw.forEach(p => {
    const brand = p.target || 'Unknown';
    if (!byBrand[brand]) byBrand[brand] = [];
    byBrand[brand].push(p);
  });
  return Object.entries(byBrand)
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 20)
    .map(([brand, entries]) => ({
      subject: 'Verify your ' + brand + ' account',
      target: brand,
      type: (entries[0] && entries[0].type) || 'Phishing',
      domains: entries.length,
      source: (entries[0] && entries[0].source) || 'OpenPhish',
      confidence: Math.round(entries.reduce((s, e) => s + e.confidence, 0) / entries.length),
      firstSeen: entries[0] && entries[0].submittedAt,
      activeUrls: entries.filter(e => e.online).length,
      lure: brand + ' account security',
      kit: 'Unknown',
    }));
}

function getMockPhishing() {
  return [
    { id:'MOCK-PT-001', source:'PhishTank', url:'https://microsoft-oauth-verify.com/login', target:'Microsoft', verified:true, online:true, submittedAt: new Date().toISOString(), type:'AiTM', confidence:99 },
    { id:'MOCK-PT-002', source:'PhishTank', url:'https://paypal-security-update.net/confirm', target:'PayPal', verified:true, online:true, submittedAt: new Date().toISOString(), type:'Credential Harvest', confidence:97 },
  ];
}

module.exports = { fetchPhishTank, fetchOpenPhish, fetchPhishingCampaigns };
