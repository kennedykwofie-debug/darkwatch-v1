const axios = require('axios');
const cache = require('../utils/cache');
const logger = require('../utils/logger');

const KEY = process.env.SHODAN_API_KEY;
const BASE = 'https://api.shodan.io';

function scoreAsset(data) {
  var score = 0;
  var ports = data.ports || [];
  var vulns = Object.keys(data.vulns || {});
  if (ports.includes(3306) || ports.includes(5432) || ports.includes(27017)) score += 40;
  if (ports.includes(3389)) score += 35;
  if (ports.includes(445) || ports.includes(139)) score += 30;
  if (ports.includes(23)) score += 30;
  if (vulns.length > 0) score += Math.min(vulns.length * 10, 40);
  if (ports.includes(22)) score += 10;
  if (ports.includes(21)) score += 15;
  if (ports.includes(80) || ports.includes(443)) score += 5;
  if (score >= 70) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 20) return 'medium';
  return 'low';
}

async function scanIP(ip) {
  var cacheKey = 'shodan:ip:' + ip;
  var cached = cache.get(cacheKey);
  if (cached) return cached;
  if (!KEY || KEY === 'your_shodan_api_key_here') return getMockAsset(ip);
  try {
    var res = await axios.get(BASE + '/shodan/host/' + ip, { params: { key: KEY }, timeout: 15000 });
    var d = res.data;
    var result = {
      ip: d.ip_str,
      hostnames: d.hostnames || [],
      org: d.org || 'Unknown',
      isp: d.isp || 'Unknown',
      country: d.country_name || 'Unknown',
      city: d.city || 'Unknown',
      os: d.os || null,
      ports: d.ports || [],
      services: (d.data || []).map(function(s) { return { port: s.port, transport: s.transport, product: s.product, version: s.version, banner: (s.data || '').substring(0, 100) }; }),
      vulns: d.vulns || {},
      vulnCount: Object.keys(d.vulns || {}).length,
      riskLevel: scoreAsset(d),
      lastScan: d.last_update || new Date().toISOString(),
      source: 'Shodan'
    };
    cache.set(cacheKey, result, 21600);
    return result;
  } catch (err) {
    logger.error('Shodan IP scan failed: ' + ip + ' - ' + err.message);
    if (err.response && err.response.status === 404) {
      return { ip: ip, hostnames: [], org: 'Unknown', isp: 'Unknown', country: 'Unknown', city: 'Unknown', os: null, ports: [], services: [], vulns: {}, vulnCount: 0, riskLevel: 'low', lastScan: new Date().toISOString(), source: 'Shodan', note: 'No data found' };
    }
    return getMockAsset(ip);
  }
}

async function discoverOrgAssets(domain) {
  var cacheKey = 'shodan:domain:' + domain;
  var cached = cache.get(cacheKey);
  if (cached) return cached;
  if (!KEY || KEY === 'your_shodan_api_key_here') return [];
  try {
    // Search for hosts matching this domain
    var query = 'hostname:' + domain;
    var res = await axios.get(BASE + '/shodan/host/search', {
      params: { key: KEY, query: query, minify: false },
      timeout: 20000
    });
    var assets = (res.data.matches || []).slice(0, 50).map(function(d) {
      return {
        ip: d.ip_str,
        hostnames: d.hostnames || [],
        org: d.org || domain,
        port: d.port,
        transport: d.transport,
        product: d.product || 'Unknown',
        version: d.version || '',
        country: d.location && d.location.country_name || 'Unknown',
        vulns: d.vulns || {},
        vulnCount: Object.keys(d.vulns || {}).length,
        riskLevel: scoreAsset({ ports: [d.port], vulns: d.vulns || {} }),
        lastScan: d.timestamp || new Date().toISOString(),
        source: 'Shodan'
      };
    });
    cache.set(cacheKey, assets, 21600);
    logger.info('Shodan: discovered ' + assets.length + ' assets for: ' + domain);
    return assets;
  } catch (err) {
    logger.error('Shodan discovery failed for ' + domain + ': ' + err.message);
    return [];
  }
}

async function scanWatchlist(ips) {
  var results = [];
  for (var i = 0; i < ips.length; i++) {
    var r = await scanIP(ips[i]);
    results.push(r);
    await new Promise(function(res) { setTimeout(res, 1000); });
  }
  return results;
}

function getMockAsset(ip) {
  return {
    ip: ip, hostnames: [], org: 'Unknown', isp: 'Unknown',
    country: 'Unknown', city: 'Unknown', os: null,
    ports: [], services: [], vulns: {}, vulnCount: 0,
    riskLevel: 'low', lastScan: new Date().toISOString(), source: 'Shodan'
  };
}

module.exports = { scanIP, discoverOrgAssets, scanWatchlist };
