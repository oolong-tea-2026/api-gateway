# api-gateway

Cloudflare Worker powering `api.wulong.dev`.

## Services

### arena-ai-leaderboards (v1)

Daily AI model leaderboard data from [arena.ai](https://arena.ai).

```
GET /arena-ai-leaderboards/v1/leaderboards                              # Latest index
GET /arena-ai-leaderboards/v1/leaderboards?date=YYYY-MM-DD              # Historical index
GET /arena-ai-leaderboards/v1/leaderboard?name={slug}                   # Latest leaderboard
GET /arena-ai-leaderboards/v1/leaderboard?name={slug}&date=YYYY-MM-DD   # Historical
```

### clawhub-skill-score (v1)

ClawHub skill search, scoring, and download API.

#### Search

Search ClawHub skills. Default limit 25, max 50.

```
GET /clawhub-skill-score/v1/search?q={query}
GET /clawhub-skill-score/v1/search?q={query}&limit=10
GET /clawhub-skill-score/v1/search?q={query}&highlightedOnly=true
GET /clawhub-skill-score/v1/search?q={query}&nonSuspiciousOnly=true
```

#### Score

Score a skill ZIP against a search query. Replicates ClawHub's exact 7-stage scoring pipeline: vector similarity (text-embedding-3-small) + lexical boost + popularity boost.

```
POST /clawhub-skill-score/v1/score
Content-Type: multipart/form-data

Fields:
  query        (string, required)  Search query
  skill        (file, required)    Skill folder as ZIP
  slug         (string, optional)  Override slug (default: zip root dir name)
  displayName  (string, optional)  Override display name
  downloads    (number, optional)  Download count (default: 0)
```

#### Download

Download a skill as ZIP from ClawHub.

```
GET /clawhub-skill-score/v1/download?slug={slug}
GET /clawhub-skill-score/v1/download?slug={slug}&version={version}
```

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

## License

MIT
