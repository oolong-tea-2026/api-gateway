// api.wulong.dev — API Gateway Worker
// Routes requests to upstream data sources and services

import { handleScore, handleSearch, handleDownload, handleServiceInfo as scoreServiceInfo } from "./clawhub-skill-score.js";

// Use GitHub raw content instead of Pages to avoid redirect issues
const UPSTREAM = "https://raw.githubusercontent.com/oolong-tea-2026/arena-ai-leaderboards/main/data";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

function errorResponse(message, status) {
  return jsonResponse({ error: message }, status);
}

async function fetchJSON(url) {
  const resp = await fetch(url, {
    headers: { "User-Agent": "api-gateway-worker" },
  });
  if (!resp.ok) return { ok: false, status: resp.status };
  return { ok: true, data: await resp.json() };
}

// GET /arena-ai-leaderboards/v1/leaderboards — list all leaderboards
// GET /arena-ai-leaderboards/v1/leaderboard?name=text — single leaderboard (latest)
// GET /arena-ai-leaderboards/v1/leaderboard?name=text&date=2026-03-19 — historical
async function handleArena(path, params) {
  if (path === "/" || path === "") {
    return jsonResponse({
      service: "arena-ai-leaderboards",
      version: "v1",
      endpoints: [
        "GET /arena-ai-leaderboards/v1/leaderboards",
        "GET /arena-ai-leaderboards/v1/leaderboard?name={slug}",
        "GET /arena-ai-leaderboards/v1/leaderboard?name={slug}&date={YYYY-MM-DD}",
      ],
    });
  }

  if (path === "/leaderboards") {
    const date = params.get("date");
    if (date) {
      const result = await fetchJSON(`${UPSTREAM}/${date}/_index.json`);
      if (!result.ok) return errorResponse(`Index not found for date: ${date}`, 404);
      return jsonResponse(result.data);
    }
    // Latest: resolve date from latest.json, then return _index.json
    const latest = await fetchJSON(`${UPSTREAM}/latest.json`);
    if (!latest.ok) return errorResponse("Failed to fetch latest index", 502);
    const dateDir = latest.data.date || latest.data.latest;
    const result = await fetchJSON(`${UPSTREAM}/${dateDir}/_index.json`);
    if (!result.ok) return errorResponse("Index not found", 404);
    return jsonResponse(result.data);
  }

  if (path === "/leaderboard") {
    const name = params.get("name");
    if (!name) return errorResponse("Missing required parameter: name", 400);

    const date = params.get("date");
    let dateDir;

    if (date) {
      dateDir = date;
    } else {
      const latest = await fetchJSON(`${UPSTREAM}/latest.json`);
      if (!latest.ok) return errorResponse("Failed to fetch latest index", 502);
      dateDir = latest.data.date || latest.data.latest;
    }

    const result = await fetchJSON(`${UPSTREAM}/${dateDir}/${name}.json`);
    if (!result.ok) return errorResponse(`Leaderboard not found: ${name}`, 404);
    return jsonResponse(result.data);
  }

  return null;
}

// POST /clawhub-skill-score/v1/score — score a skill against a query
async function handleSkillScore(path, request, env) {
  if (path === "/" || path === "") {
    return jsonResponse(scoreServiceInfo());
  }

  if (path === "/score") {
    const result = await handleScore(request, env);
    return jsonResponse(result.data || { error: result.error }, result.status);
  }

  if (path === "/search") {
    const result = await handleSearch(request, env);
    return jsonResponse(result.data || { error: result.error }, result.status);
  }

  if (path === "/download") {
    const result = await handleDownload(request, env);
    if (result.raw) return result.raw; // binary response
    return jsonResponse({ error: result.error }, result.status);
  }

  return null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // Root — service directory
    if (url.pathname === "/" || url.pathname === "") {
      if (request.method !== "GET") return errorResponse("Method not allowed", 405);
      return jsonResponse({
        name: "api.wulong.dev",
        services: {
          "arena-ai-leaderboards": {
            version: "v1",
            base: "/arena-ai-leaderboards/v1",
          },
          "clawhub-skill-score": {
            version: "v1",
            base: "/clawhub-skill-score/v1",
          },
        },
      });
    }

    // Route: /arena-ai-leaderboards/v1/...
    const arenaPrefix = "/arena-ai-leaderboards/v1";
    if (url.pathname.startsWith(arenaPrefix)) {
      if (request.method !== "GET") return errorResponse("Method not allowed", 405);
      const subpath = url.pathname.slice(arenaPrefix.length) || "/";
      const result = await handleArena(subpath, url.searchParams);
      if (result) return result;
    }

    // Route: /clawhub-skill-score/v1/...
    const scorePrefix = "/clawhub-skill-score/v1";
    if (url.pathname.startsWith(scorePrefix)) {
      const subpath = url.pathname.slice(scorePrefix.length) || "/";
      const result = await handleSkillScore(subpath, request, env);
      if (result) return result;
    }

    return errorResponse("Not found", 404);
  },
};
