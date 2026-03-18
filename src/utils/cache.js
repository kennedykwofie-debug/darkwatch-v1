const NodeCache = require('node-cache');
const logger = require('./logger');
const cache = new NodeCache({ useClones: false });
const TTL = {
  SHORT: parseInt(process.env.CACHE_TTL_SHORT) || 300,
  MEDIUM: parseInt(process.env.CACHE_TTL_MEDIUM) || 900,
  LONG: parseInt(process.env.CACHE_TTL_LONG) || 3600,
};
function get(key) { return cache.get(key) ?? null; }
function set(key, value, ttl = TTL.MEDIUM) { cache.set(key, value, ttl); }
function flush(prefix = null) {
  if (!prefix) { cache.flushAll(); logger.info('Cache flushed'); }
  else { cache.keys().filter(k => k.startsWith(prefix)).forEach(k => cache.del(k)); }
}
function stats() { return { keys: cache.keys().length, hits: cache.getStats().hits, misses: cache.getStats().misses }; }
module.exports = { get, set, flush, stats, TTL };
