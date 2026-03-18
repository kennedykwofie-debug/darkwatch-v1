const express = require('express');
const aggregator = require('../feeds/aggregator');
const monitor = require('../feeds/monitor');
const shodan = require('../feeds/shodan');
const creds = require('../feeds/credentials');
const cacheUtil = require('../utils/cache');
const logger = require('../utils/logger');
const axios = require('axios');
const router = express.Router();

// ── Threat Intel routes ──────────────────────────────────────────────────────
router.get('/threats', async function(req, res) {
  try {
    var q = req.query;
    var data = await aggregator.aggregateAll({ industry: q.industry||'all', region: q.region||'all', severity: q.severity||'all', limit: Math.min(parseInt(q.limit)||50, 200) });
    res.json({ success: true, data: data });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/iocs', async function(req, res) {
  try {
    var iocs = await aggregator.aggregateIoCs({ limit: Math.min(parseInt(req.query.limit)||100, 500) });
    res.json({ success: true, data: iocs, total: iocs.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/actors', async function(req, res) {
  try {
    var q = req.query;
    var actors = await aggregator.fetchThreatActors({ limit: 50 });
    if (q.nation) actors = actors.filter(function(a) { return a.nation && a.nation.toLowerCase() === q.nation.toLowerCase(); });
    res.json({ success: true, data: actors.slice(0, parseInt(q.limit)||40), total: actors.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/cves', async function(req, res) {
  try {
    var q = req.query;
    var list = q.source === 'kev' ? await aggregator.fetchRecentKEV({ limit: parseInt(q.limit)||20 }) : await aggregator.fetchRecentCVEs({ limit: parseInt(q.limit)||20 });
    if (q.exploited === 'true') list = list.filter(function(c) { return c.exploited; });
    res.json({ success: true, data: list, total: list.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/phishing', async function(req, res) {
  try {
    var data = await aggregator.fetchPhishing();
    res.json({ success: true, data: data.slice(0, parseInt(req.query.limit)||20), total: data.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/stats', async function(req, res) {
  try { res.json({ success: true, data: await aggregator.getStats() }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/health', function(req, res) {
  var hibpKey = process.env.HIBP_API_KEY;
  var shodanKey = process.env.SHODAN_API_KEY;
  res.json({
    status: 'ok', timestamp: new Date().toISOString(), cache: cacheUtil.stats(),
    feeds: {
      otx: process.env.OTX_API_KEY && !process.env.OTX_API_KEY.startsWith('your_') ? 'configured' : 'no-key',
      urlhaus: 'public', bazaar: 'public', feodo: 'public', threatfox: 'public', mitre: 'public', cisa: 'public',
      hibp: (!hibpKey || hibpKey === 'your_hibp_api_key_here') ? 'no-key' : 'configured',
      shodan: (!shodanKey || shodanKey === 'your_shodan_api_key_here') ? 'no-key' : 'configured'
    }
  });
});

router.post('/cache/flush', function(req, res) {
  cacheUtil.flush((req.body||{}).prefix || null);
  res.json({ success: true, message: 'Cache flushed' });
});

// ── DNS resolution helper ────────────────────────────────────────────────────
async function resolveDomain(domain) {
  try {
    var res = await axios.get('https://dns.google/resolve', {
      params: { name: domain, type: 'A' }, timeout: 5000
    });
    var answers = (res.data.Answer || []).filter(function(r) { return r.type === 1; });
    return answers.map(function(r) { return r.data; });
  } catch (e) {
    logger.warn('DNS resolution failed for ' + domain + ': ' + e.message);
    return [];
  }
}

// ── Asset Monitor routes ─────────────────────────────────────────────────────
router.get('/monitor/status', function(req, res) {
  try { res.json({ success: true, data: monitor.getState() }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/monitor/scan', async function(req, res) {
  try {
    res.json({ success: true, message: 'Scan started', data: { started: new Date().toISOString() } });
    monitor.runScanCycle().catch(function(e) { logger.error('Manual scan error: ' + e.message); });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// POST /api/v1/monitor/watchlist - add IP or domain (domain auto-resolves to IPs)
router.post('/monitor/watchlist', async function(req, res) {
  try {
    var body = req.body || {};
    var resolvedIPs = [];

    if (body.ip) {
      monitor.addWatchedIP(body.ip);
      resolvedIPs.push(body.ip);
    }

    if (body.domain) {
      monitor.addWatchedDomain(body.domain);
      // Auto-resolve domain to IPs and add them
      var ips = await resolveDomain(body.domain);
      ips.forEach(function(ip) {
        monitor.addWatchedIP(ip);
        resolvedIPs.push(ip);
      });
      logger.info('Domain ' + body.domain + ' resolved to: ' + ips.join(', '));
    }

    if (body.email) monitor.addWatchedEmail(body.email);
    if (body.credDomain) monitor.addWatchedDomain(body.credDomain);

    res.json({ success: true, state: monitor.getState(), resolvedIPs: resolvedIPs });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.delete('/monitor/watchlist', function(req, res) {
  try {
    var body = req.body || {};
    if (body.type && body.value) monitor.removeWatched(body.type, body.value);
    res.json({ success: true, state: monitor.getState() });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/v1/monitor/assets - MERGED: IP scan results + domain discovery results
router.get('/monitor/assets', function(req, res) {
  try {
    var state = monitor.getState();
    var all = [];

    // Add IP scan results (these are individual host scans)
    (state.assetResults || []).forEach(function(asset) {
      if (!asset || !asset.ip) return;
      // IP scan returns ports array - create one row per IP showing all ports
      var ports = (asset.ports || []);
      if (ports.length === 0) {
        all.push({
          ip: asset.ip,
          hostnames: asset.hostnames || [],
          org: asset.org || 'Unknown',
          port: null,
          product: 'No open ports found',
          version: '',
          country: asset.country || 'Unknown',
          vulns: asset.vulns || {},
          vulnCount: asset.vulnCount || 0,
          riskLevel: asset.riskLevel || 'low',
          lastScan: asset.lastScan,
          source: asset.source || 'Shodan',
          note: asset.note || null
        });
      } else {
        // One row per open port
        (asset.services || [{ port: ports[0], product: 'Unknown', version: '' }]).forEach(function(svc) {
          all.push({
            ip: asset.ip,
            hostnames: asset.hostnames || [],
            org: asset.org || 'Unknown',
            port: svc.port,
            product: svc.product || 'Unknown',
            version: svc.version || '',
            country: asset.country || 'Unknown',
            vulns: asset.vulns || {},
            vulnCount: asset.vulnCount || 0,
            riskLevel: asset.riskLevel || 'low',
            lastScan: asset.lastScan,
            source: asset.source || 'Shodan'
          });
        });
      }
    });

    // Add domain discovery results
    (state.domainAssets || []).forEach(function(d) {
      (d.assets || []).forEach(function(a) {
        all.push(Object.assign({}, a, { org: d.domain }));
      });
    });

    // Sort by risk level
    var order = { critical: 0, high: 1, medium: 2, low: 3 };
    all.sort(function(a, b) { return (order[a.riskLevel] || 4) - (order[b.riskLevel] || 4); });

    res.json({ success: true, data: all, total: all.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/monitor/ip/:ip', async function(req, res) {
  try { res.json({ success: true, data: await shodan.scanIP(req.params.ip) }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/monitor/alerts', function(req, res) {
  try {
    var state = monitor.getState();
    res.json({ success: true, data: state.alerts || [], total: (state.alerts || []).length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

// ── Credential Leak routes ───────────────────────────────────────────────────
router.get('/credentials/status', function(req, res) {
  try {
    var state = monitor.getState();
    var summary = state.emailResults && state.emailResults.length ? creds.summarise(state.emailResults) : null;
    res.json({ success: true, data: state.emailResults || [], emails: state.watchedEmails || [], summary: summary });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.post('/credentials/check', async function(req, res) {
  try {
    var email = (req.body || {}).email;
    if (!email) return res.status(400).json({ success: false, error: 'email required' });
    res.json({ success: true, data: await creds.checkEmail(email) });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/credentials/email/:email', async function(req, res) {
  try { res.json({ success: true, data: await creds.checkEmail(decodeURIComponent(req.params.email)) }); }
  catch (err) { res.status(500).json({ success: false, error: err.message }); }
});

router.get('/credentials/breaches', async function(req, res) {
  try {
    var breaches = await creds.getAllBreaches();
    res.json({ success: true, data: breaches, total: breaches.length });
  } catch (err) { res.status(500).json({ success: false, error: err.message }); }
});


// DNS resolution endpoint - resolves domain to IPs using Google DoH
router.get('/monitor/dns/:domain', async function(req, res) {
  try {
    var domain = req.params.domain;
    var axios = require('axios');
    var result = await axios.get('https://dns.google/resolve', {
      params: { name: domain, type: 'A' },
      timeout: 8000
    });
    var answers = (result.data.Answer || []).filter(function(r) { return r.type === 1; });
    var ips = answers.map(function(r) { return r.data; });
    // Also get CNAMEs
    var cnames = (result.data.Answer || []).filter(function(r) { return r.type === 5; }).map(function(r) { return r.data.replace(/\.$/, ''); });
    res.json({ success: true, domain: domain, ips: ips, cnames: cnames, status: result.data.Status });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});


// ── Domain Verification & Bulk Domain Breach Scanning ────────────────────────

// GET /api/v1/credentials/verify/:domain - get verification token + check DNS
router.get('/credentials/verify/:domain', async function(req, res) {
  try {
    var domain = req.params.domain;
    var result = await creds.checkDomainVerification(domain);
    res.json({ success: true, data: result });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/v1/credentials/token/:domain - just get the token (no DNS check)
router.get('/credentials/token/:domain', function(req, res) {
  try {
    var domain = req.params.domain;
    var token = creds.getVerificationToken(domain);
    res.json({ success: true, domain: domain, token: token, txtRecord: token, instruction: 'Add a DNS TXT record to ' + domain + ' with value: ' + token });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/v1/credentials/domain/:domain - bulk breach scan for verified domain
router.get('/credentials/domain/:domain', async function(req, res) {
  try {
    var result = await creds.checkDomainBreaches(req.params.domain);
    res.json({ success: true, data: result });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/v1/credentials/verified - list all verified domains
router.get('/credentials/verified', function(req, res) {
  try {
    res.json({ success: true, data: creds.getVerifiedDomains() });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});


// ── Domain Verification Routes ────────────────────────────────────────────────

// GET /api/v1/credentials/domain/verify/request/:domain - get HIBP TXT token
router.get('/credentials/domain/verify/request/:domain', async function(req, res) {
  try {
    var result = await creds.requestDomainVerification(req.params.domain);
    res.json(result);
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/v1/credentials/domain/verify/check/:domain - check if DNS TXT record detected
router.get('/credentials/domain/verify/check/:domain', async function(req, res) {
  try {
    var result = await creds.checkDomainVerified(req.params.domain);
    res.json({ success: true, data: result });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/v1/credentials/domain/scan/:domain - full bulk scan of verified domain
router.get('/credentials/domain/scan/:domain', async function(req, res) {
  try {
    var result = await creds.scanVerifiedDomain(req.params.domain);
    res.json({ success: true, data: result });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

// GET /api/v1/credentials/domain/breaches/:domain - alias for scan
router.get('/credentials/domain/breaches/:domain', async function(req, res) {
  try {
    var result = await creds.scanVerifiedDomain(req.params.domain);
    res.json({ success: true, data: result });
  } catch(err) { res.status(500).json({ success: false, error: err.message }); }
});

module.exports = router;
