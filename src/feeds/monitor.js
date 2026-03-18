const shodan = require('./shodan');
const creds = require('./credentials');
const logger = require('../utils/logger');
const fs = require('fs');
const path = require('path');

// Persist watchlist to disk so it survives server restarts
var DATA_FILE = path.join('/app', 'data', 'watchlist.json');
// Fallback for local dev
if (!fs.existsSync('/app')) DATA_FILE = path.join(__dirname, '../../data', 'watchlist.json');

function loadFromDisk() {
  try {
    var dir = path.dirname(DATA_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    if (fs.existsSync(DATA_FILE)) {
      var raw = fs.readFileSync(DATA_FILE, 'utf8');
      var saved = JSON.parse(raw);
      logger.info('Monitor: loaded watchlist from disk - ' + (saved.watchedEmails||[]).length + ' emails, ' + (saved.watchedIPs||[]).length + ' IPs');
      return saved;
    }
  } catch(e) { logger.error('Monitor: failed to load watchlist: ' + e.message); }
  return {};
}

function saveToDisk(s) {
  try {
    var dir = path.dirname(DATA_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify({
      watchedIPs: s.watchedIPs,
      watchedDomains: s.watchedDomains,
      watchedEmails: s.watchedEmails
    }), 'utf8');
  } catch(e) { logger.error('Monitor: failed to save watchlist: ' + e.message); }
}

var saved = loadFromDisk();
var state = {
  watchedIPs: saved.watchedIPs || [],
  watchedDomains: saved.watchedDomains || [],
  watchedEmails: saved.watchedEmails || [],
  assetResults: [],
  domainAssets: [],
  emailResults: [],
  alerts: [],
  lastScan: null
};

function addWatchedIP(ip) {
  if (!state.watchedIPs.includes(ip)) {
    state.watchedIPs.push(ip);
    saveToDisk(state);
    logger.info('Watchlist: added IP ' + ip);
  }
}

function addWatchedDomain(domain) {
  if (!state.watchedDomains.includes(domain)) {
    state.watchedDomains.push(domain);
    saveToDisk(state);
    logger.info('Watchlist: added domain ' + domain);
  }
}

function addWatchedEmail(em) {
  if (!state.watchedEmails.includes(em)) {
    state.watchedEmails.push(em);
    saveToDisk(state);
    logger.info('Watchlist: added email ' + em);
  }
}

function addCredDomain(domain) { addWatchedDomain(domain); }

function removeWatched(type, value) {
  if (type === 'ip') state.watchedIPs = state.watchedIPs.filter(function(x) { return x !== value; });
  if (type === 'domain') state.watchedDomains = state.watchedDomains.filter(function(x) { return x !== value; });
  if (type === 'email') {
    state.watchedEmails = state.watchedEmails.filter(function(x) { return x !== value; });
    state.emailResults = state.emailResults.filter(function(x) { return x.email !== value; });
  }
  saveToDisk(state);
}

async function runScanCycle() {
  logger.info('Monitor: starting scan cycle...');
  var newAlerts = [];
  var ips = state.watchedIPs;
  var domains = state.watchedDomains;
  var emails = state.watchedEmails;

  if (ips.length === 0 && domains.length === 0 && emails.length === 0) {
    logger.info('Monitor: watchlist empty, skipping scan');
    state.lastScan = new Date().toISOString();
    return { alerts: [], assetsScanned: 0 };
  }

  if (ips.length > 0) {
    try {
      var ipResults = await shodan.scanWatchlist(ips);
      var prevAssets = {};
      state.assetResults.forEach(function(a) { if (a && a.ip) prevAssets[a.ip] = a; });
      ipResults.forEach(function(asset) {
        if (!asset || !asset.ip) return;
        var prev = prevAssets[asset.ip];
        if (prev) {
          var newPorts = (asset.ports || []).filter(function(p) { return !(prev.ports || []).includes(p); });
          if (newPorts.length) newAlerts.push({ type: 'new_port', severity: 'high', message: 'New port(s) on ' + asset.ip + ': ' + newPorts.join(', '), asset: asset.ip, timestamp: new Date().toISOString() });
          var newVulns = Object.keys(asset.vulns || {}).filter(function(v) { return !prev.vulns || !prev.vulns[v]; });
          if (newVulns.length) newAlerts.push({ type: 'new_vuln', severity: 'critical', message: 'New CVE on ' + asset.ip + ': ' + newVulns.join(', '), asset: asset.ip, timestamp: new Date().toISOString() });
        }
      });
      state.assetResults = ipResults.filter(function(r) { return r && r.ip; });
    } catch(e) { logger.error('IP scan error: ' + e.message); }
  } else { state.assetResults = []; }

  if (domains.length > 0) {
    try {
      var domainAssets = [];
      for (var i = 0; i < domains.length; i++) {
        var assets = await shodan.discoverOrgAssets(domains[i]);
        domainAssets.push({ domain: domains[i], assets: assets, scannedAt: new Date().toISOString() });
        assets.forEach(function(a) {
          if (a.riskLevel === 'critical') newAlerts.push({ type: 'critical_asset', severity: 'critical', message: 'Critical asset: ' + a.ip + ':' + a.port + ' (' + a.product + ') for ' + domains[i], asset: a.ip, timestamp: new Date().toISOString() });
        });
      }
      state.domainAssets = domainAssets;
    } catch(e) { logger.error('Domain discovery error: ' + e.message); }
  } else { state.domainAssets = []; }

  if (emails.length > 0) {
    try {
      var emailResults = await creds.checkEmails(emails);
      var prevResults = {};
      state.emailResults.forEach(function(r) { if (r && r.email) prevResults[r.email] = r; });
      emailResults.forEach(function(r) {
        if (!r || !r.email) return;
        var prev = prevResults[r.email];
        var prevCount = prev ? (prev.breachCount || 0) : 0;
        if (r.breachCount > prevCount) {
          var newBreaches = (r.breachNames || []).filter(function(n) { return !prev || !(prev.breachNames || []).includes(n); });
          newAlerts.push({ type: 'credential_leak', severity: r.breachCount >= 5 ? 'critical' : 'high', message: r.email + ' found in ' + r.breachCount + ' breach(es)' + (newBreaches.length ? ' incl. ' + newBreaches.slice(0, 3).join(', ') : ''), email: r.email, timestamp: new Date().toISOString() });
        }
      });
      state.emailResults = emailResults;
    } catch(e) { logger.error('Email check error: ' + e.message); }
  } else { state.emailResults = []; }

  if (newAlerts.length > 0) {
    state.alerts = newAlerts.concat(state.alerts).slice(0, 100);
    logger.info('Monitor: ' + newAlerts.length + ' new alerts');
  }
  state.lastScan = new Date().toISOString();
  logger.info('Monitor: scan cycle complete');
  return { alerts: newAlerts, assetsScanned: state.assetResults.length };
}

function getState() {
  return {
    watchedIPs: state.watchedIPs,
    watchedDomains: state.watchedDomains,
    watchedEmails: state.watchedEmails,
    assetResults: state.assetResults,
    domainAssets: state.domainAssets,
    emailResults: state.emailResults,
    alerts: state.alerts.slice(0, 50),
    lastScan: state.lastScan
  };
}

module.exports = { addWatchedIP, addWatchedDomain, addWatchedEmail, addCredDomain, removeWatched, runScanCycle, getState };
