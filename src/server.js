require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const logger = require('./utils/logger');
const apiRoutes = require('./routes/api');
const monitor = require('./feeds/monitor');

if (!fs.existsSync('logs')) fs.mkdirSync('logs');

const app = express();
const PORT = process.env.PORT || 3001;
const SCAN_INTERVAL_MS = parseInt(process.env.SCAN_INTERVAL_HOURS || '6') * 60 * 60 * 1000;

// Helmet with relaxed CSP for our dashboard
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameSrc: ["'none'"]
    }
  }
}));

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'DELETE'] }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 500 }));
app.use(express.json());
app.use('/api/v1', apiRoutes);

const publicDir = path.join(__dirname, '..', 'public');
app.use(express.static(publicDir));
app.get('*', function(req, res) {
  var i = path.join(publicDir, 'index.html');
  fs.existsSync(i) ? res.sendFile(i) : res.json({ message: 'DARKWATCH API' });
});

app.listen(PORT, function() {
  logger.info('DARKWATCH started on http://localhost:' + PORT);

  // Pre-warm caches
  setTimeout(function() {
    logger.info('Pre-warming caches...');
    require('./feeds/actors').fetchThreatActors({ limit: 50 })
      .then(function(g) { logger.info('MITRE warm: ' + g.length + ' groups'); })
      .catch(function(e) { logger.warn('MITRE warm failed: ' + e.message); });
    require('./feeds/cves').fetchCISAKEV()
      .then(function() { logger.info('CISA KEV warmed'); })
      .catch(function() {});
    require('./feeds/phishing').fetchPhishingCampaigns()
      .then(function(p) { logger.info('Phishing warm: ' + p.length); })
      .catch(function() {});
  }, 2000);

  // Initial monitoring scan
  setTimeout(function() {
    logger.info('Running initial monitoring scan...');
    monitor.runScanCycle()
      .then(function(r) { logger.info('Initial scan: ' + r.assetsScanned + ' assets, ' + r.alerts.length + ' alerts'); })
      .catch(function(e) { logger.error('Initial scan error: ' + e.message); });
  }, 15000);

  // Continuous monitoring every N hours
  setInterval(function() {
    logger.info('Scheduled monitoring scan...');
    monitor.runScanCycle()
      .then(function(r) { logger.info('Scan done: ' + r.assetsScanned + ' assets'); })
      .catch(function(e) { logger.error('Scheduled scan error: ' + e.message); });
  }, SCAN_INTERVAL_MS);

  logger.info('Monitoring: every ' + (SCAN_INTERVAL_MS / 3600000) + 'h');
});

module.exports = app;
