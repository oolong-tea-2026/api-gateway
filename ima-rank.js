// ima-rank.js — IMA Skills Rank API
// Proxies ranking data from GitHub repo (oolong-tea-2026/ima-skills-rank)

const GITHUB_RAW_BASE = 'https://raw.githubusercontent.com/oolong-tea-2026/ima-skills-rank/main/data';
const CACHE_TTL = 300; // 5 min cache

async function githubFetch(path) {
  const url = `${GITHUB_RAW_BASE}/${path}`;
  const resp = await fetch(url, {
    headers: { 'User-Agent': 'ima-rank-api/1.0' },
    cf: { cacheTtl: CACHE_TTL, cacheEverything: true },
  });
  if (!resp.ok) {
    return { error: `GitHub fetch error: ${resp.status}`, status: resp.status === 404 ? 404 : 502 };
  }
  const data = await resp.json();
  return { data, status: 200 };
}

export async function handleConfig(request) {
  if (request.method !== 'GET') return { error: 'Method not allowed', status: 405 };
  return githubFetch('config.json');
}

export async function handleIndex(request) {
  if (request.method !== 'GET') return { error: 'Method not allowed', status: 405 };
  return githubFetch('index.json');
}

export async function handleSnapshot(request) {
  if (request.method !== 'GET') return { error: 'Method not allowed', status: 405 };

  const url = new URL(request.url);
  let date = url.searchParams.get('date');

  if (!date) {
    return { error: 'Missing required parameter: date (YYYY-MM-DD or "latest")', status: 400 };
  }

  if (date === 'latest') {
    // Fetch index to get latest date
    const indexResult = await githubFetch('index.json');
    if (indexResult.error) return indexResult;
    date = indexResult.data.latest;
    if (!date) return { error: 'No snapshots available', status: 404 };
  }

  // Validate date format
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    return { error: 'Invalid date format. Use YYYY-MM-DD or "latest"', status: 400 };
  }

  return githubFetch(`snapshots/${date}.json`);
}

export function handleRankInfo() {
  return {
    service: 'ima-rank',
    version: 'v1',
    description: 'IMA Skills ClawHub search ranking tracker',
    endpoints: [
      { method: 'GET', path: '/ima-rank/v1/config', description: 'Monitoring configuration (skills + keywords)' },
      { method: 'GET', path: '/ima-rank/v1/index', description: 'List all snapshot dates' },
      { method: 'GET', path: '/ima-rank/v1/snapshot?date=YYYY-MM-DD', description: 'Get ranking snapshot for a date (or "latest")' },
    ],
  };
}
