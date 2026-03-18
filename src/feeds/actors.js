/** Threat Actor Intelligence - MITRE ATT&CK */
const axios = require('axios');
const cache = require('../utils/cache');
const logger = require('../utils/logger');
const MITRE_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';
function extractNation(name, aliases, desc) {
  const t = [name, ...(aliases || []), desc].join(' ').toLowerCase();
  if (['china','prc','apt41','winnti','hafnyum'].some(k => t.includes(k))) return 'China';
  if (['russia','apt28','apt29','sandworm','cozy bear','fancy bear'].some(k => t.includes(k))) return 'Russia';
  if (['north korea','dprk','lazarus','kimsuky'].some(k => t.includes(k))) return 'North Korea';
  if (['iran','charming kitten','apt33'].some(k => t.includes(k))) return 'Iran';
  return 'Unknown';
}
function classifyType(desc = '') {
  const d = desc.toLowerCase();
  if (d.includes('nation')||d.includes('state')||d.includes('government')) return 'State-Sponsored';
  if (d.includes('criminal')||d.includes('financial gain')) return 'Cybercriminal';
  if (d.includes('hacktivist')) return 'Hacktivist';
  return 'APT';
}
function extractMotives(desc = '') {
  const d = desc.toLowerCase(); const m = [];
  if (d.includes('espionage')||d.includes('intelligence')) m.push('espionage');
  if (d.includes('financial')||d.includes('profit')) m.push('financial');
  if (d.includes('disrupt')||d.includes('sabotage')) m.push('disruption');
  return m.length ? m : ['unknown'];
}
function parseSTIXGroups(bundle) {
  const objects = bundle.objects || [];
  const groups = objects.filter(o => o.type === 'intrusion-set').map(g => ({
    id: g.id, name: g.name, aliases: g.aliases || [],
    description: (g.description || '').substring(0,300),
    source: 'MITRE ATT&CK', activity: 'MODERATE',
    nation: extractNation(g.name, g.aliases, g.description),
    type: classifyType(g.description), motives: extractMotives(g.description),
    targets: [], ttps: [],
    url: g.external_references?.find(r => r.source_name === 'mitre-attack')?.url || '',
    attackId: g.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id || '',
  }));
  const techniques = Object.fromEntries(objects.filter(o => o.type === 'attack-pattern').map(t => [t.id, t.name]));
  const gTTP = {};
  objects.filter(o => o.type === 'relationship' && o.relationship_type === 'uses' && o.target_ref?.startsWith('attack-pattern')).forEach(r => { if (!gTTP[r.source_ref]) gTTP[r.source_ref]=[]; if (techniques[r.target_ref]) gTTP[r.source_ref].push(techniques[r.target_ref]); });
  return groups.map(g => ({ ...g, ttps: (gTTP[g.id] || []).slice(0,6) })).slice(0,40);
}
async function fetchThreatActors({ limit = 20 } = {}) {
  const cached = cache.get('mitre:groups'); if (cached) return cached.slice(0,limit);
  try {
    logger.info('MITRE: fetching...');
    const res = await axios.get(MITRE_URL, { timeout: 30000 });
    const g = parseSTIXGroups(res.data);
    cache.set('mitre:groups',g,cache.TTL.LONG); logger.info(`MITRE: ${g.length} groups`); return g.slice(0,limit);
  } catch(err) { logger.error('MITRE failed',err.message); return getMockActors(); }
}
function getMockActors() { return [{ id:'mock-g0096', name:'APT41 (WINNTIB', aliases:['WINNTI'], description:'Chinese state-sponsored group.', source:'MITRE', activity:'ACTIVE', nation:'China', type:'State-Sponsored', motives:['espionage'], targets:['technology'], ttps:['Spear Phishing'], url:'https://attack.mitre.org/groups/G0096/', attackId:'G0096' }]; }
module.exports = { fetchThreatActors };