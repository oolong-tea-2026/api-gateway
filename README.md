# api-gateway

Cloudflare Worker powering `api.wulong.dev`.

## Services

### arena-ai-leaderboards (v1)

Daily AI model leaderboard data from [arena.ai](https://arena.ai).

```
GET /arena-ai-leaderboards/v1/leaderboards                         # Latest index
GET /arena-ai-leaderboards/v1/leaderboards?date=YYYY-MM-DD         # Historical index
GET /arena-ai-leaderboards/v1/leaderboard?name={slug}              # Latest leaderboard
GET /arena-ai-leaderboards/v1/leaderboard?name={slug}&date=YYYY-MM-DD  # Historical
```

## Deployment

```bash
# Upload worker to Cloudflare
curl -X PUT "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/workers/scripts/api-gateway" \
  -H "Authorization: Bearer $CF_TOKEN" \
  -F "worker.js=@worker.js;type=application/javascript+module" \
  -F 'metadata={"main_module":"worker.js"};type=application/json'
```

## License

MIT
