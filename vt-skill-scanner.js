/**
 * vt-skill-scanner — VirusTotal skill scanning API
 *
 * Endpoints:
 *   POST /scan   — Upload skill ZIP, build deterministic ZIP, submit to VT, return results
 *   GET  /result — Poll scan results by SHA-256 hash
 */

// ── Deterministic ZIP (STORE, matching ClawHub's sorted paths + fixed mtime) ──

const FIXED_DOS_DATE = 0x0021; // 1980-01-01
const FIXED_DOS_TIME = 0x0000; // 00:00:00

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function buildDeterministicZip(entries) {
  const sorted = [...entries].sort((a, b) => a.path.localeCompare(b.path));
  const localHeaders = [];
  const centralHeaders = [];
  let offset = 0;

  for (const entry of sorted) {
    const nameBytes = new TextEncoder().encode(entry.path);
    const data = entry.bytes;
    const crc = crc32(data);

    // Local file header
    const local = new Uint8Array(30 + nameBytes.length + data.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(8, 0, true); // STORE
    lv.setUint16(10, FIXED_DOS_TIME, true);
    lv.setUint16(12, FIXED_DOS_DATE, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, data.length, true);
    lv.setUint32(22, data.length, true);
    lv.setUint16(26, nameBytes.length, true);
    local.set(nameBytes, 30);
    local.set(data, 30 + nameBytes.length);
    localHeaders.push(local);

    // Central directory header
    const central = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(central.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(10, 0, true); // STORE
    cv.setUint16(12, FIXED_DOS_TIME, true);
    cv.setUint16(14, FIXED_DOS_DATE, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, data.length, true);
    cv.setUint32(24, data.length, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint32(42, offset, true);
    central.set(nameBytes, 46);
    centralHeaders.push(central);

    offset += local.length;
  }

  const centralDirOffset = offset;
  const centralDirSize = centralHeaders.reduce((s, h) => s + h.length, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, sorted.length, true);
  ev.setUint16(10, sorted.length, true);
  ev.setUint32(12, centralDirSize, true);
  ev.setUint32(16, centralDirOffset, true);

  const total = offset + centralDirSize + 22;
  const result = new Uint8Array(total);
  let pos = 0;
  for (const h of localHeaders) { result.set(h, pos); pos += h.length; }
  for (const h of centralHeaders) { result.set(h, pos); pos += h.length; }
  result.set(eocd, pos);
  return result;
}

// ── ZIP parser (read uploaded ZIP) ──────────────────────────────────

function parseZip(buffer) {
  const view = new DataView(buffer.buffer || buffer);
  const bytes = new Uint8Array(buffer);
  const files = [];

  // Find End of Central Directory
  let eocdOffset = -1;
  for (let i = bytes.length - 22; i >= 0; i--) {
    if (view.getUint32(i, true) === 0x06054b50) { eocdOffset = i; break; }
  }
  if (eocdOffset < 0) throw new Error("Invalid ZIP: EOCD not found");

  const cdOffset = view.getUint32(eocdOffset + 16, true);
  const cdCount = view.getUint16(eocdOffset + 10, true);
  let pos = cdOffset;

  for (let i = 0; i < cdCount; i++) {
    if (view.getUint32(pos, true) !== 0x02014b50) break;
    const compMethod = view.getUint16(pos + 10, true);
    const compSize = view.getUint32(pos + 20, true);
    const uncompSize = view.getUint32(pos + 24, true);
    const nameLen = view.getUint16(pos + 28, true);
    const extraLen = view.getUint16(pos + 30, true);
    const commentLen = view.getUint16(pos + 32, true);
    const localOffset = view.getUint32(pos + 42, true);
    const name = new TextDecoder().decode(bytes.slice(pos + 46, pos + 46 + nameLen));
    pos += 46 + nameLen + extraLen + commentLen;

    // Read from local header
    const localNameLen = view.getUint16(localOffset + 26, true);
    const localExtraLen = view.getUint16(localOffset + 28, true);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen;

    if (compMethod !== 0) continue; // skip non-STORE (we'll handle most ZIPs)
    const content = bytes.slice(dataStart, dataStart + uncompSize);

    if (!name.endsWith("/")) {
      files.push({ name, bytes: content });
    }
  }

  return files;
}

// ── Normalize ZIP entries (strip root dir prefix) ───────────────────

function normalizeEntries(files) {
  // Find common root prefix (e.g., "my-skill/")
  let rootDir = "";
  const skillMd = files.find(f => f.name.toLowerCase().endsWith("skill.md"));
  if (skillMd) {
    const idx = skillMd.name.lastIndexOf("/");
    if (idx > 0) rootDir = skillMd.name.slice(0, idx + 1);
  }

  const entries = [];
  for (const f of files) {
    let rel = f.name;
    if (rootDir && rel.startsWith(rootDir)) {
      rel = rel.slice(rootDir.length);
    }
    if (!rel || rel.endsWith("/")) continue;
    // Skip dotfiles
    if (rel.split("/").some(p => p.startsWith("."))) continue;
    entries.push({ path: rel, bytes: new Uint8Array(f.bytes) });
  }
  return entries;
}

// ── VirusTotal API ──────────────────────────────────────────────────

async function vtCheck(apiKey, sha256) {
  const resp = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, {
    headers: { "x-apikey": apiKey },
  });
  if (resp.status === 404) return null;
  if (!resp.ok) throw new Error(`VT API ${resp.status}`);
  return resp.json();
}

async function vtUpload(apiKey, zipBytes) {
  const form = new FormData();
  form.append("file", new Blob([zipBytes], { type: "application/zip" }), "skill.zip");
  const resp = await fetch("https://www.virustotal.com/api/v3/files", {
    method: "POST",
    headers: { "x-apikey": apiKey },
    body: form,
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`VT upload ${resp.status}: ${text}`);
  }
  return resp.json();
}

// ── Format results ──────────────────────────────────────────────────

function formatResults(sha256, vtData) {
  if (!vtData) {
    return {
      sha256,
      status: "pending",
      url: `https://www.virustotal.com/gui/file/${sha256}`,
      engines: null,
      codeInsight: null,
    };
  }

  const attrs = vtData?.data?.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const aiResult = (attrs.crowdsourced_ai_results || []).find(r => r.category === "code_insight");

  const enginesTotal = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.harmless || 0);
  let engineVerdict = "pending";
  if (enginesTotal > 0) {
    if (stats.malicious > 0) engineVerdict = "malicious";
    else if (stats.suspicious > 0) engineVerdict = "suspicious";
    else if (stats.harmless > 0) engineVerdict = "clean";
    else engineVerdict = "undetected";
  }

  return {
    sha256,
    status: aiResult ? "complete" : (enginesTotal > 0 ? "engines_complete" : "pending"),
    url: `https://www.virustotal.com/gui/file/${sha256}`,
    engines: {
      verdict: engineVerdict,
      total: enginesTotal,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
    },
    codeInsight: aiResult ? {
      verdict: aiResult.verdict,
      analysis: aiResult.analysis,
      source: aiResult.source,
    } : null,
  };
}

// ── Handlers ────────────────────────────────────────────────────────

export async function handleScan(request, env) {
  if (request.method !== "POST") {
    return { error: "Method not allowed. Use POST with multipart/form-data.", status: 405 };
  }

  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("multipart/form-data")) {
    return { error: "Content-Type must be multipart/form-data", status: 400 };
  }

  const apiKey = env.VT_API_KEY;
  if (!apiKey) {
    return { error: "Server misconfigured: missing VT_API_KEY", status: 500 };
  }

  const formData = await request.formData();
  const file = formData.get("skill");
  if (!file || typeof file === "string" || !file.arrayBuffer) {
    return { error: "Missing required field: skill (ZIP file)", status: 400 };
  }

  if (file.size > 5 * 1024 * 1024) {
    return { error: "ZIP file too large (max 5MB)", status: 413 };
  }

  try {
    // Parse uploaded ZIP
    const rawBytes = new Uint8Array(await file.arrayBuffer());
    const rawFiles = parseZip(rawBytes);
    if (rawFiles.length === 0) {
      return { error: "ZIP contains no files", status: 400 };
    }

    // Normalize and rebuild as deterministic ZIP
    const entries = normalizeEntries(rawFiles);
    if (entries.length === 0) {
      return { error: "No valid skill files found in ZIP", status: 400 };
    }

    const deterministicZip = buildDeterministicZip(entries);

    // Compute SHA-256
    const hashBuffer = await crypto.subtle.digest("SHA-256", deterministicZip);
    const sha256 = [...new Uint8Array(hashBuffer)].map(b => b.toString(16).padStart(2, "0")).join("");

    // Check VT
    let vtData = null;
    try {
      vtData = await vtCheck(apiKey, sha256);
    } catch (e) {
      // VT check failed, proceed to upload
    }

    if (vtData) {
      // Already in VT, return current results
      return {
        data: {
          ...formatResults(sha256, vtData),
          uploaded: false,
          files: entries.length,
          zipSize: deterministicZip.length,
        },
        status: 200,
      };
    }

    // Upload to VT
    const uploadResult = await vtUpload(apiKey, deterministicZip);

    return {
      data: {
        ...formatResults(sha256, null),
        uploaded: true,
        analysisId: uploadResult?.data?.id,
        files: entries.length,
        zipSize: deterministicZip.length,
      },
      status: 200,
    };
  } catch (e) {
    return { error: e.message, status: 422 };
  }
}

export async function handleResult(request, env) {
  if (request.method !== "GET") {
    return { error: "Method not allowed. Use GET.", status: 405 };
  }

  const apiKey = env.VT_API_KEY;
  if (!apiKey) {
    return { error: "Server misconfigured: missing VT_API_KEY", status: 500 };
  }

  const url = new URL(request.url);
  const sha256 = url.searchParams.get("sha256");
  if (!sha256 || !/^[a-f0-9]{64}$/.test(sha256)) {
    return { error: "Missing or invalid sha256 parameter (64 hex chars)", status: 400 };
  }

  try {
    const vtData = await vtCheck(apiKey, sha256);
    return { data: formatResults(sha256, vtData), status: 200 };
  } catch (e) {
    return { error: e.message, status: 502 };
  }
}

export function handleScannerInfo() {
  return {
    service: "vt-skill-scanner",
    version: "v1",
    endpoints: [
      { method: "POST", path: "/vt-skill-scanner/v1/scan", description: "Upload skill ZIP for VirusTotal scanning" },
      { method: "GET", path: "/vt-skill-scanner/v1/result?sha256=<hash>", description: "Poll scan results by SHA-256" },
    ],
  };
}
