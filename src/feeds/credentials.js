const axios = require('axios');
const cache = require('../utils/cache');
const logger = require('../utils/logger');

const HIBP_KEY = process.env.HIBP_API_KEY;
const HIBP_BASE = 'https://haveibeenpwned.com/api/v3';

// ── Email-level check (works immediately with API key) ────────────────────────
async function checkEmail(email) {
  var cacheKey = 'creds:email:' + email;
  var cached = cache.get(cacheKey);
  if (cached) return cached;
  if (!HIBP_KEY || HIBP_KEY === 'your_hibp_api_key_here') return getMockEmail(email);
  try {
    var res = await axios.get(HIBP_BASE + '/breachedaccount/' + encodeURIComponent(email) + '?truncateResponse=false', {
      headers: { 'hibp-api-key': HIBP_KEY, 'User-Agent': 'DARKWATCH-ThreatIntel/1.0' },
      timeout: 15000
    });
    var breaches = (res.data || []).map(function(b) {
      return { name: b.Name, domain: b.Domain, breachDate: b.BreachDate, pwnCount: b.PwnCount, dataClasses: b.DataClasses, isSensitive: b.IsSensitive };
    });
    var result = { email: email, breachCount: breaches.length, breaches: breaches, breachNames: breaches.map(function(b){return b.name;}), riskLevel: breaches.length >= 5 ? 'critical' : breaches.length >= 2 ? 'high' : breaches.length >= 1 ? 'medium' : 'clean', lastChecked: new Date().toISOString(), source: 'HaveIBeenPwned' };
    cache.set(cacheKey, result, 43200);
    return result;
  } catch(err) {
    if (err.response && err.response.status === 404) {
      var clean = { email: email, breachCount: 0, breaches: [], breachNames: [], riskLevel: 'clean', lastChecked: new Date().toISOString(), source: 'HaveIBeenPwned' };
      cache.set(cacheKey, clean, 43200);
      return clean;
    }
    if (err.response && err.response.status === 429) { await new Promise(function(r){setTimeout(r,1600);}); return checkEmail(email); }
    logger.error('HIBP email check failed: ' + err.message);
    return getMockEmail(email);
  }
}

async function checkEmails(emails) {
  var results = [];
  for (var i = 0; i < emails.length; i++) {
    results.push(await checkEmail(emails[i]));
    if (i < emails.length - 1) await new Promise(function(r){setTimeout(r,1600);});
  }
  return results;
}

// ── Domain verification ────────────────────────────────────────────────────────
// Step 1: Request a verification token from HIBP
async function requestDomainVerification(domain) {
  if (!HIBP_KEY || HIBP_KEY === 'your_hibp_api_key_here') {
    return { success: false, error: 'HIBP API key not configured' };
  }
  try {
    // HIBP verification token endpoint
    var res = await axios.get(HIBP_BASE + '/domainverification/' + encodeURIComponent(domain), {
      headers: { 'hibp-api-key': HIBP_KEY, 'User-Agent': 'DARKWATCH-ThreatIntel/1.0' },
      timeout: 15000
    });
    return { success: true, token: res.data.DomainVerificationToken || res.data, domain: domain };
  } catch(err) {
    if (err.response && err.response.status === 404) {
      return { success: false, error: 'Domain not found - add it to your HIBP dashboard first at haveibeenpwned.com/DomainSearch' };
    }
    return { success: false, error: err.response ? (err.response.data || err.message) : err.message };
  }
}

// Step 2: Check if domain is verified (HIBP verifies automatically when TXT record is detected)
async function checkDomainVerified(domain) {
  if (!HIBP_KEY || HIBP_KEY === 'your_hibp_api_key_here') return { verified: false };
  try {
    var res = await axios.get(HIBP_BASE + '/breacheddomain/' + encodeURIComponent(domain), {
      headers: { 'hibp-api-key': HIBP_KEY, 'User-Agent': 'DARKWATCH-ThreatIntel/1.0' },
      timeout: 20000
    });
    // If we get a 200, the domain is verified and we have breach data
    var data = res.data || {};
    var emails = Object.keys(data);
    var breachedEmails = emails.map(function(em) {
      return { email: em + '@' + domain, alias: em, breachNames: data[em], breachCount: data[em].length };
    });
    return { verified: true, domain: domain, breachedEmails: breachedEmails, totalBreached: emails.length };
  } catch(err) {
    if (err.response && err.response.status === 403) {
      return { verified: false, reason: 'Domain not yet verified - add the TXT record to your DNS' };
    }
    if (err.response && err.response.status === 404) {
      return { verified: false, reason: 'Domain not added to HIBP yet' };
    }
    return { verified: false, reason: err.message };
  }
}

// Step 3: Full domain scan (once verified)
async function scanVerifiedDomain(domain) {
  var cacheKey = 'creds:domain:' + domain;
  var cached = cache.get(cacheKey);
  if (cached) return cached;
  var result = await checkDomainVerified(domain);
  if (result.verified) {
    cache.set(cacheKey, result, 3600); // 1h cache for domain scans
    logger.info('HIBP domain scan: ' + result.totalBreached + ' breached accounts on ' + domain);
  }
  return result;
}

// ── Global breach feed ─────────────────────────────────────────────────────────
async function getAllBreaches() {
  var cacheKey = 'creds:allbreaches';
  var cached = cache.get(cacheKey);
  if (cached) return cached;
  if (!HIBP_KEY || HIBP_KEY === 'your_hibp_api_key_here') return getMockBreachList();
  try {
    var res = await axios.get(HIBP_BASE + '/breaches', {
      headers: { 'hibp-api-key': HIBP_KEY, 'User-Agent': 'DARKWATCH-ThreatIntel/1.0' },
      timeout: 15000
    });
    var breaches = (res.data || []).sort(function(a,b){return new Date(b.AddedDate)-new Date(a.AddedDate);}).slice(0,20).map(function(b){
      return { name: b.Name, domain: b.Domain, breachDate: b.BreachDate, addedDate: b.AddedDate, pwnCount: b.PwnCount, dataClasses: b.DataClasses, isSensitive: b.IsSensitive, isVerified: b.IsVerified, description: (b.Description||'').replace(/<[^>]+>/g,'').substring(0,200), source: 'HaveIBeenPwned' };
    });
    cache.set(cacheKey, breaches, 3600);
    return breaches;
  } catch(err) {
    logger.error('HIBP all breaches failed: ' + err.message);
    return getMockBreachList();
  }
}

function summarise(results) {
  var uniqueBreachNames = new Set();
  var criticalEmails = 0;
  results.forEach(function(r) { (r.breachNames||[]).forEach(function(n){uniqueBreachNames.add(n);}); if(r.riskLevel==='critical'||r.riskLevel==='high') criticalEmails++; });
  return { totalEmails: results.length, exposedEmails: results.filter(function(r){return r.breachCount>0;}).length, totalBreachInstances: results.reduce(function(a,r){return a+(r.breachCount||0);},0), uniqueBreaches: Array.from(uniqueBreachNames), criticalEmails: criticalEmails, cleanEmails: results.filter(function(r){return r.breachCount===0;}).length };
}

function getMockEmail(email) {
  return { email: email, breachCount: 0, breaches: [], breachNames: [], riskLevel: 'clean', lastChecked: new Date().toISOString(), source: 'HaveIBeenPwned (mock)' };
}

function getMockBreachList() {
  return [
    { name: 'RockYou2024', domain: 'rockyou.net', breachDate: '2024-06-04', addedDate: '2024-07-05', pwnCount: 9948575739, dataClasses: ['Passwords'], isVerified: true, source: 'HaveIBeenPwned' },
    { name: 'Trello', domain: 'trello.com', breachDate: '2024-01-22', addedDate: '2024-01-24', pwnCount: 15115516, dataClasses: ['Email addresses', 'Usernames', 'Names'], isVerified: true, source: 'HaveIBeenPwned' },
    { name: 'Infosys McCamish', domain: 'infosysbpm.com', breachDate: '2023-11-03', addedDate: '2024-05-07', pwnCount: 6078263, dataClasses: ['SSNs', 'Bank account numbers'], isSensitive: true, source: 'HaveIBeenPwned' }
  ];
}

module.exports = { checkEmail, checkEmails, summarise, getAllBreaches, requestDomainVerification, checkDomainVerified, scanVerifiedDomain };
