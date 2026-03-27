# api-gateway

Cloudflare Worker powering `api.wulong.dev`.

## Services

### arena-ai-leaderboards (v1)

Daily AI model leaderboard data from [arena.ai](https://arena.ai).

#### List leaderboards

```bash
# Latest index
curl https://api.wulong.dev/arena-ai-leaderboards/v1/leaderboards

# Historical index
curl https://api.wulong.dev/arena-ai-leaderboards/v1/leaderboards?date=2026-03-20
```

#### Get leaderboard

```bash
# Latest
curl https://api.wulong.dev/arena-ai-leaderboards/v1/leaderboard?name=text

# Historical
curl https://api.wulong.dev/arena-ai-leaderboards/v1/leaderboard?name=text&date=2026-03-20
```

---

### clawhub-skill-score (v1)

ClawHub skill search, scoring, download, and detail API.

Web UI: [clawhub-scorer.wulong.dev](https://clawhub-scorer.wulong.dev)

#### Search

Search ClawHub skills. Default limit 25, max 50.

```bash
# Basic search
curl "https://api.wulong.dev/clawhub-skill-score/v1/search?q=video+generation"

# With limit
curl "https://api.wulong.dev/clawhub-skill-score/v1/search?q=video+generation&limit=10"

# Filtered
curl "https://api.wulong.dev/clawhub-skill-score/v1/search?q=video&highlightedOnly=true&nonSuspiciousOnly=true"
```

#### Detail

Get skill metadata (displayName, downloads, summary, etc.) from ClawHub.

```bash
curl "https://api.wulong.dev/clawhub-skill-score/v1/detail?slug=weather"
```

#### Score

Score a skill ZIP against a search query. Replicates ClawHub's exact 7-stage scoring pipeline: vector similarity (text-embedding-3-small) + lexical boost + popularity boost.

```bash
# Score a local skill ZIP
curl -X POST "https://api.wulong.dev/clawhub-skill-score/v1/score" \
  -F "query=video generation" \
  -F "skill=@my-skill.zip" \
  -F "downloads=42"

# With optional overrides
curl -X POST "https://api.wulong.dev/clawhub-skill-score/v1/score" \
  -F "query=video generation" \
  -F "skill=@my-skill.zip" \
  -F "slug=my-custom-slug" \
  -F "displayName=My Skill" \
  -F "downloads=100"
```

#### Download

Download a skill as ZIP from ClawHub.

```bash
# Latest version
curl -o weather.zip "https://api.wulong.dev/clawhub-skill-score/v1/download?slug=weather"

# Specific version
curl -o weather.zip "https://api.wulong.dev/clawhub-skill-score/v1/download?slug=weather&version=1.0.0"
```

---

### ima-rank (v1)

IMA Skills ClawHub search ranking tracker. Data sourced from [ima-skills-rank](https://github.com/oolong-tea-2026/ima-skills-rank) repo.

Web UI: [ima-skills-rank.wulong.dev](https://ima-skills-rank.wulong.dev)

#### Config

Get monitoring configuration (tracked skills and keywords).

```bash
curl https://api.wulong.dev/ima-rank/v1/config
```

#### Index

List all available snapshot dates.

```bash
curl https://api.wulong.dev/ima-rank/v1/index
```

#### Snapshot

Get ranking snapshot for a specific date or latest.

```bash
# Latest
curl "https://api.wulong.dev/ima-rank/v1/snapshot?date=latest"

# Specific date
curl "https://api.wulong.dev/ima-rank/v1/snapshot?date=2026-03-26"
```

---

### vt-skill-scanner (v1)

VirusTotal security scanner for OpenClaw skills. Uploads skill ZIP to VirusTotal, returns AV engine results and Code Insight (AI analysis).

Internally rebuilds uploaded ZIPs as **deterministic ZIPs** (fixed timestamps, sorted paths) to ensure consistent SHA-256 hashes and VT cache hits.

#### Scan

Upload a skill ZIP for scanning. Returns existing VT results if the hash is already known, otherwise uploads to VT.

```bash
curl -X POST "https://api.wulong.dev/vt-skill-scanner/v1/scan" \
  -F "skill=@my-skill.zip"
```

Response:

```json
{
  "sha256": "0165a28d...",
  "status": "engines_complete",
  "url": "https://www.virustotal.com/gui/file/0165a28d...",
  "engines": {
    "verdict": "undetected",
    "total": 64,
    "malicious": 0,
    "suspicious": 0,
    "harmless": 0,
    "undetected": 64
  },
  "codeInsight": null,
  "uploaded": false,
  "files": 6,
  "zipSize": 138856
}
```

Status values: `pending` → `engines_complete` → `complete` (when Code Insight is available).

#### Result

Poll scan results by SHA-256 hash. Use the hash from the `/scan` response.

```bash
curl "https://api.wulong.dev/vt-skill-scanner/v1/result?sha256=0165a28de24ca95394520c5998cddf43d084491dca499211ddcfe06d08c3071c"
```

When Code Insight is ready, `codeInsight` will contain the AI verdict and analysis:

```json
{
  "codeInsight": {
    "verdict": "benign",
    "analysis": "The skill bundle is classified as benign...",
    "source": "Code Insight"
  }
}
```

---

### oc-skill-scanner (v1)

OpenClaw security evaluator for skills. Replicates ClawHub's moderation pipeline: static regex scan + LLM security evaluation (gpt-5-mini).

#### Scan

Upload a skill ZIP for full security evaluation. Returns static scan findings + LLM verdict with 5-dimension assessment.

```bash
curl -X POST "https://api.wulong.dev/oc-skill-scanner/v1/scan" \
  -F "skill=@my-skill.zip"
```

Response:

```json
{
  "verdict": "clean",
  "staticScan": {
    "verdict": "clean",
    "reasonCodes": [],
    "findings": []
  },
  "llmEval": {
    "verdict": "benign",
    "confidence": "high",
    "summary": "The skill is internally consistent with its stated purpose.",
    "dimensions": {
      "purpose_capability": { "status": "ok", "detail": "..." },
      "instruction_scope": { "status": "ok", "detail": "..." },
      "install_mechanism": { "status": "ok", "detail": "..." },
      "environment_proportionality": { "status": "ok", "detail": "..." },
      "persistence_privilege": { "status": "ok", "detail": "..." }
    },
    "guidance": "..."
  },
  "files": 6,
  "usage": { "prompt_tokens": 12234, "completion_tokens": 2049, "total_tokens": 14283 }
}
```

Combined verdict: `clean` / `suspicious` / `malicious` (worst of static + LLM).

---

## Deployment

Push a `release-*` tag to trigger GitHub Actions deployment.

```bash
git tag release-N
git push origin release-N
```

### Secrets (GitHub Actions)

| Secret | Description |
|--------|-------------|
| `CF_ACCOUNT_ID` | Cloudflare account ID |
| `CF_API_TOKEN` | Cloudflare API token |
| `EMBED_BASE_URL` | Azure OpenAI embedding endpoint |
| `EMBED_API_KEY` | Azure OpenAI API key |
| `CLAWHUB_TOKEN` | ClawHub API token |
| `VT_API_KEY` | VirusTotal API key |

## License

MIT
