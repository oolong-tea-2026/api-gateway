// clawhub-skill-score — ClawHub skill scoring API
// POST /clawhub-skill-score/v1/score
//
// Replicates ClawHub's exact scoring pipeline:
//   vectorScore (cosine similarity via text-embedding-3-small)
//   + lexicalBoost (slug/name token matching)
//   + popularityBoost (log1p(downloads) * 0.08)

// ── Constants (matching ClawHub source) ─────────────────────────────

const EMBEDDING_MAX_CHARS = 12_000;
const MAX_OTHER_FILES = 40;

const SLUG_EXACT_BOOST = 1.4;
const SLUG_PREFIX_BOOST = 0.8;
const NAME_EXACT_BOOST = 1.1;
const NAME_PREFIX_BOOST = 0.6;
const POPULARITY_FACTOR = 0.08;

// Extensions that enter embedding (from ClawHub packages/clawdhub/src/schema/textFiles.ts)
// .md/.mdx pass the set but are excluded from otherFiles
const TEXT_FILE_EXTENSIONS = new Set([
  "md", "mdx", "txt", "json", "json5", "yaml", "yml", "toml",
  "js", "cjs", "mjs", "ts", "tsx", "jsx", "py", "sh", "rb",
  "go", "rs", "swift", "kt", "java", "cs", "cpp", "c", "h",
  "hpp", "sql", "csv", "ini", "cfg", "env", "xml", "html",
  "css", "scss", "sass", "svg",
]);

// ── JSZip-free zip parsing ──────────────────────────────────────────

/**
 * Minimal ZIP parser — extracts text files from a ZIP buffer.
 * Supports DEFLATE (method 8) and STORED (method 0).
 * No external dependencies.
 *
 * Uses the Central Directory (at end of ZIP) to get reliable file sizes,
 * which fixes the bug where local file headers have compressedSize=0
 * when the data descriptor flag (bit 3 of general purpose flags) is set.
 */
function parseZip(buffer) {
  const view = new DataView(buffer);
  const entries = [];

  // ── Step 1: Find End of Central Directory (EOCD) record ──
  // EOCD signature = 0x06054b50, located near end of file.
  // Scan backwards from end (EOCD can have a trailing comment up to 65535 bytes).
  let eocdOffset = -1;
  const searchStart = Math.max(0, buffer.byteLength - 65557); // 22 (min EOCD) + 65535 (max comment)
  for (let i = buffer.byteLength - 22; i >= searchStart; i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset === -1) {
    throw new Error("Invalid ZIP: End of Central Directory not found");
  }

  const cdEntryCount = view.getUint16(eocdOffset + 10, true);
  let cdOffset = view.getUint32(eocdOffset + 16, true);

  // ── Step 2: Walk Central Directory entries ──
  // Central Directory file header signature = 0x02014b50
  for (let i = 0; i < cdEntryCount; i++) {
    if (cdOffset + 46 > buffer.byteLength) break;
    const sig = view.getUint32(cdOffset, true);
    if (sig !== 0x02014b50) break;

    const method = view.getUint16(cdOffset + 10, true);
    const compressedSize = view.getUint32(cdOffset + 20, true);
    const uncompressedSize = view.getUint32(cdOffset + 24, true);
    const nameLen = view.getUint16(cdOffset + 28, true);
    const extraLen = view.getUint16(cdOffset + 30, true);
    const commentLen = view.getUint16(cdOffset + 32, true);
    const localHeaderOffset = view.getUint32(cdOffset + 42, true);

    const nameBytes = new Uint8Array(buffer, cdOffset + 46, nameLen);
    const name = new TextDecoder().decode(nameBytes);

    // Advance to next CD entry
    cdOffset += 46 + nameLen + extraLen + commentLen;

    // Skip directories
    if (name.endsWith("/")) continue;

    // ── Step 3: Read actual data from local file header ──
    // Local header gives us nameLen + extraLen to find data start
    // (local extra can differ from CD extra, so we must re-read)
    if (localHeaderOffset + 30 > buffer.byteLength) continue;
    const localNameLen = view.getUint16(localHeaderOffset + 26, true);
    const localExtraLen = view.getUint16(localHeaderOffset + 28, true);
    const dataOffset = localHeaderOffset + 30 + localNameLen + localExtraLen;

    if (dataOffset + compressedSize > buffer.byteLength) continue;
    const rawData = new Uint8Array(buffer, dataOffset, compressedSize);

    let data;
    if (method === 0) {
      // STORED
      data = rawData;
    } else if (method === 8) {
      // DEFLATE — use DecompressionStream
      data = { compressed: rawData, uncompressedSize };
    } else {
      data = null; // unsupported method
    }
    entries.push({ name, data, method });
  }

  return entries;
}

async function decompressDeflate(compressed) {
  // Workers support DecompressionStream with "deflate-raw"
  const ds = new DecompressionStream("deflate-raw");
  const writer = ds.writable.getWriter();
  writer.write(compressed);
  writer.close();
  const reader = ds.readable.getReader();
  const chunks = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const result = new Uint8Array(total);
  let pos = 0;
  for (const c of chunks) {
    result.set(c, pos);
    pos += c.length;
  }
  return result;
}

async function extractTextFiles(zipBuffer) {
  const entries = parseZip(zipBuffer);
  const files = [];

  for (const entry of entries) {
    if (!entry.data) continue;

    let bytes;
    if (entry.method === 8) {
      try {
        bytes = await decompressDeflate(entry.data.compressed);
      } catch {
        continue; // skip files we can't decompress
      }
    } else {
      bytes = entry.data;
    }

    const content = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    files.push({ name: entry.name, content });
  }

  return files;
}

// ── Frontmatter parsing ─────────────────────────────────────────────

function parseFrontmatter(content) {
  if (!content.startsWith("---")) return { fm: {}, body: content };
  const parts = content.split("---");
  if (parts.length < 3) return { fm: {}, body: content };

  const fmText = parts[1].trim();
  const body = parts.slice(2).join("---").trim();

  // Simple YAML parser (no dependency)
  const fm = {};
  let currentKey = null;
  let currentValue = "";
  let isMultiline = false;

  for (const line of fmText.split("\n")) {
    if (isMultiline) {
      if (line.match(/^\s/) && !line.match(/^\S/)) {
        currentValue += " " + line.trim();
        continue;
      } else {
        fm[currentKey] = currentValue.trim();
        isMultiline = false;
      }
    }

    const match = line.match(/^(\w[\w-]*)\s*:\s*(.*)/);
    if (match) {
      currentKey = match[1];
      const val = match[2].trim();
      if (val === ">" || val === "|") {
        isMultiline = true;
        currentValue = "";
      } else {
        fm[currentKey] = val.replace(/^["']|["']$/g, "");
      }
    }
  }
  if (isMultiline && currentKey) {
    fm[currentKey] = currentValue.trim();
  }

  return { fm, body };
}

// ── Build embedding text (matching ClawHub's buildEmbeddingText) ────

function buildEmbeddingText(skillMdContent, otherFiles) {
  const { fm } = parseFrontmatter(skillMdContent);

  // 1. Frontmatter fields (newline-separated)
  const fmParts = [];
  for (const key of ["name", "description", "homepage", "website", "url", "emoji"]) {
    if (fm[key]) fmParts.push(fm[key]);
  }
  const fmText = fmParts.join("\n");

  // 2. SKILL.md full text (including frontmatter block)
  const parts = fmText ? [fmText, skillMdContent] : [skillMdContent];

  // 3. Other non-.md text files with "# {path}" headers
  for (const { name, content } of otherFiles.slice(0, MAX_OTHER_FILES)) {
    parts.push(`# ${name}\n${content}`);
  }

  return parts.join("\n\n").slice(0, EMBEDDING_MAX_CHARS);
}

// ── Tokenize (ClawHub: /[a-z0-9]+/g) ───────────────────────────────

function tokenize(text) {
  return (text.toLowerCase().match(/[a-z0-9]+/g) || []);
}

// ── Cosine similarity ───────────────────────────────────────────────

function cosineSimilarity(a, b) {
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  normA = Math.sqrt(normA);
  normB = Math.sqrt(normB);
  if (normA === 0 || normB === 0) return 0;
  return dot / (normA * normB);
}

// ── Lexical boost ───────────────────────────────────────────────────

function computeLexicalBoost(queryTokens, slug, displayName) {
  const slugTokens = tokenize(slug);
  const nameTokens = tokenize(displayName);

  let slugBoost = 0, slugMatch = "none";
  if (slugTokens.length && queryTokens.length) {
    if (queryTokens.every(qt => slugTokens.some(st => qt === st))) {
      slugBoost = SLUG_EXACT_BOOST; slugMatch = "SLUG_EXACT";
    } else if (queryTokens.every(qt => slugTokens.some(st => st.startsWith(qt)))) {
      slugBoost = SLUG_PREFIX_BOOST; slugMatch = "SLUG_PREFIX";
    }
  }

  let nameBoost = 0, nameMatch = "none";
  if (nameTokens.length && queryTokens.length) {
    if (queryTokens.every(qt => nameTokens.some(nt => qt === nt))) {
      nameBoost = NAME_EXACT_BOOST; nameMatch = "NAME_EXACT";
    } else if (queryTokens.every(qt => nameTokens.some(nt => nt.startsWith(qt)))) {
      nameBoost = NAME_PREFIX_BOOST; nameMatch = "NAME_PREFIX";
    }
  }

  return {
    slugBoost, slugMatch, slugTokens,
    nameBoost, nameMatch, nameTokens,
    total: slugBoost + nameBoost,
  };
}

// ── Popularity boost ────────────────────────────────────────────────

function computePopularityBoost(downloads) {
  return Math.log1p(downloads) * POPULARITY_FACTOR;
}

// ── Token filter (.some — lenient) ──────────────────────────────────

function passesTokenFilter(queryTokens, slug, displayName, summary) {
  const textTokens = tokenize(`${displayName} ${slug} ${summary}`);
  return queryTokens.some(qt => textTokens.some(tt => tt.startsWith(qt)));
}

// ── Embedding via Azure OpenAI (matches ClawHub's model exactly) ────

async function getEmbeddings(texts, env) {
  // Use Azure OpenAI to match ClawHub's exact embedding model
  const baseUrl = env.EMBED_BASE_URL;
  const apiKey = env.EMBED_API_KEY;

  if (!baseUrl || !apiKey) {
    throw new Error("Server misconfigured: missing EMBED_BASE_URL or EMBED_API_KEY");
  }

  const resp = await fetch(baseUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "api-key": apiKey,
    },
    body: JSON.stringify({
      input: texts,
      model: "text-embedding-3-small",
    }),
  });

  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Embedding API error ${resp.status}: ${body}`);
  }

  const data = await resp.json();
  return data.data
    .sort((a, b) => a.index - b.index)
    .map(d => d.embedding);
}

// ── Extract metadata from SKILL.md ──────────────────────────────────

function extractMetadata(skillMdContent, zipRootDir) {
  const { fm, body } = parseFrontmatter(skillMdContent);

  let displayName = fm.name || "";
  if (!displayName) {
    for (const line of body.split("\n")) {
      if (line.trim().startsWith("# ")) {
        displayName = line.trim().slice(2).trim();
        break;
      }
    }
  }

  let summary = fm.description || "";
  if (!summary) {
    for (const line of body.split("\n")) {
      const l = line.trim();
      if (l && !l.startsWith("#")) {
        summary = l.slice(0, 160);
        break;
      }
    }
  }

  // Slug from directory name (zip root)
  const slug = zipRootDir || fm.name || "unknown";

  return { slug, displayName, summary, description: fm.description || "" };
}

// ── Process zip and compute score ───────────────────────────────────

async function computeScore(zipBuffer, query, opts, env) {
  const files = await extractTextFiles(zipBuffer);

  if (files.length === 0) {
    throw new Error("ZIP is empty or contains no readable files");
  }

  // Find SKILL.md — search by basename regardless of directory depth.
  // This handles: flat ZIPs, single-root ZIPs, and arbitrarily nested ZIPs.
  const skillMdEntry = files.find(f => {
    const basename = f.name.split("/").pop();
    return basename === "SKILL.md" || basename?.toLowerCase() === "skill.md";
  });
  if (!skillMdEntry) {
    throw new Error("SKILL.md not found in ZIP");
  }

  // Derive root directory from SKILL.md's path (everything before the basename)
  // e.g. "my-skill/sub/SKILL.md" → rootDir = "my-skill/sub", so normalize strips that prefix.
  let rootDir = "";
  const skillMdDir = skillMdEntry.name.lastIndexOf("/");
  if (skillMdDir > 0) {
    rootDir = skillMdEntry.name.slice(0, skillMdDir); // "my-skill/sub"
  }

  // Normalize paths (strip root prefix + slash)
  const normalize = (name) => rootDir ? name.slice(rootDir.length + 1) : name;

  const skillMdContent = skillMdEntry.content;
  const meta = extractMetadata(skillMdContent, rootDir);

  // Apply overrides
  const slug = opts.slug || meta.slug;
  const displayName = opts.displayName || meta.displayName || slug;
  const downloads = opts.downloads ?? 0;

  // Collect other files for embedding
  const otherFiles = [];
  for (const f of files) {
    const rel = normalize(f.name);
    if (!rel || f.name === skillMdEntry.name) continue;

    const parts = rel.split("/");
    // Skip dotfiles/directories
    if (parts.some(p => p.startsWith("."))) continue;
    // Skip node_modules, __macosx
    if (parts.some(p => p.toLowerCase() === "node_modules" || p.toLowerCase() === "__macosx")) continue;

    const ext = rel.split(".").pop()?.toLowerCase() || "";
    if (!TEXT_FILE_EXTENSIONS.has(ext)) continue;
    // Exclude .md/.mdx from otherFiles (they're in TEXT_FILE_EXTENSIONS but filtered for embedding)
    if (ext === "md" || ext === "mdx") continue;

    otherFiles.push({ name: rel, content: f.content });
  }

  // Build embedding text
  const embeddingText = buildEmbeddingText(skillMdContent, otherFiles);

  // Get embeddings
  const queryTokens = tokenize(query);
  const [queryEmb, skillEmb] = await getEmbeddings([query, embeddingText], env);

  // Compute scores
  const vectorScore = cosineSimilarity(queryEmb, skillEmb);
  const lexical = computeLexicalBoost(queryTokens, slug, displayName);
  const popularityBoost = computePopularityBoost(downloads);
  const finalScore = vectorScore + lexical.total + popularityBoost;

  // Token filter
  const passesFilter = passesTokenFilter(queryTokens, slug, displayName, meta.summary);

  // Slug recall
  const candidateSlug = queryTokens.join("-");
  const slugRecall = candidateSlug === slug;

  return {
    query,
    queryTokens,
    skill: {
      slug,
      displayName,
      description: meta.description,
    },
    scores: {
      final: round4(finalScore),
      breakdown: {
        vector: round4(vectorScore),
        lexical: {
          total: round4(lexical.total),
          slug: { boost: lexical.slugBoost, match: lexical.slugMatch, tokens: lexical.slugTokens },
          name: { boost: lexical.nameBoost, match: lexical.nameMatch, tokens: lexical.nameTokens },
        },
        popularity: {
          boost: round4(popularityBoost),
          downloads,
        },
      },
    },
    diagnostics: {
      passesTokenFilter: passesFilter,
      slugRecall,
      candidateSlug,
      embeddingTextLength: embeddingText.length,
      embeddingMaxChars: EMBEDDING_MAX_CHARS,
      embeddingTruncated: embeddingText.length >= EMBEDDING_MAX_CHARS,
      filesInZip: files.length,
      filesInEmbedding: otherFiles.length + 1, // +1 for SKILL.md
      embeddingTextFirst500: embeddingText.slice(0, 500),
      embeddingTextLast500: embeddingText.slice(-500),
      otherFileNames: otherFiles.map(f => f.name),
    },
  };
}

function round4(n) {
  return Math.round(n * 10000) / 10000;
}

// ── Multipart form-data parser (preserves binary) ───────────────────

function parseMultipart(buffer, contentType) {
  const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^\s;]+))/);
  if (!boundaryMatch) throw new Error("No boundary in content-type");
  const boundary = boundaryMatch[1] || boundaryMatch[2];
  const boundaryBytes = new TextEncoder().encode("--" + boundary);
  const data = new Uint8Array(buffer);

  const fields = {};
  const files = {};

  // Find all boundary positions
  const positions = [];
  for (let i = 0; i <= data.length - boundaryBytes.length; i++) {
    let match = true;
    for (let j = 0; j < boundaryBytes.length; j++) {
      if (data[i + j] !== boundaryBytes[j]) { match = false; break; }
    }
    if (match) positions.push(i);
  }

  for (let p = 0; p < positions.length - 1; p++) {
    const start = positions[p] + boundaryBytes.length;
    const end = positions[p + 1];

    // Skip CRLF after boundary
    let headerStart = start;
    if (data[headerStart] === 0x0d && data[headerStart + 1] === 0x0a) headerStart += 2;

    // Find header/body separator (CRLFCRLF)
    let bodyStart = -1;
    for (let i = headerStart; i < end - 3; i++) {
      if (data[i] === 0x0d && data[i + 1] === 0x0a && data[i + 2] === 0x0d && data[i + 3] === 0x0a) {
        bodyStart = i + 4;
        break;
      }
    }
    if (bodyStart === -1) continue;

    const headerText = new TextDecoder().decode(data.slice(headerStart, bodyStart - 4));
    
    // Trim trailing CRLF before next boundary
    let bodyEnd = end;
    if (bodyEnd >= 2 && data[bodyEnd - 1] === 0x0a && data[bodyEnd - 2] === 0x0d) bodyEnd -= 2;

    const bodyData = data.slice(bodyStart, bodyEnd);

    // Parse name from Content-Disposition
    const nameMatch = headerText.match(/name="([^"]+)"/);
    if (!nameMatch) continue;
    const name = nameMatch[1];

    const isFile = headerText.includes("filename=");
    if (isFile) {
      files[name] = bodyData.buffer.slice(bodyData.byteOffset, bodyData.byteOffset + bodyData.byteLength);
    } else {
      fields[name] = new TextDecoder().decode(bodyData);
    }
  }

  return { fields, files };
}

// ── Request handler ─────────────────────────────────────────────────

export async function handleScore(request, env) {
  if (request.method !== "POST") {
    return { error: "Method not allowed. Use POST.", status: 405 };
  }

  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("multipart/form-data")) {
    return { error: "Content-Type must be multipart/form-data", status: 400 };
  }

  if (!env.EMBED_BASE_URL || !env.EMBED_API_KEY) {
    return { error: "Server misconfigured: missing embedding credentials", status: 500 };
  }

  // Parse multipart manually to handle binary file correctly
  const body = await request.arrayBuffer();
  const { fields, files } = parseMultipart(body, contentType);

  const query = fields.query;
  if (!query || !query.trim()) {
    return { error: "Missing required field: query", status: 400 };
  }

  const zipBuffer = files.skill;
  if (!zipBuffer) {
    return { error: "Missing required field: skill (ZIP file)", status: 400 };
  }

  // Size limit: 5MB
  if (zipBuffer.byteLength > 5 * 1024 * 1024) {
    return { error: "ZIP file too large (max 5MB)", status: 413 };
  }

  // Optional overrides
  const slug = fields.slug || undefined;
  const displayName = fields.displayName || undefined;
  const downloadsStr = fields.downloads;
  const downloads = downloadsStr != null ? parseInt(downloadsStr, 10) : 0;

  if (downloadsStr != null && isNaN(downloads)) {
    return { error: "downloads must be a number", status: 400 };
  }

  try {
    const result = await computeScore(zipBuffer, query.trim(), { slug, displayName, downloads }, env);
    return { data: result, status: 200 };
  } catch (e) {
    return { error: e.message, status: 422 };
  }
}

// ── Detail (proxy ClawHub skill detail API) ─────────────────────────

export async function handleDetail(request, env) {
  if (request.method !== "GET") {
    return { error: "Method not allowed. Use GET.", status: 405 };
  }

  const url = new URL(request.url);
  const slug = url.searchParams.get("slug");
  if (!slug || !slug.trim()) {
    return { error: "Missing required parameter: slug", status: 400 };
  }

  const token = env.CLAWHUB_TOKEN;
  if (!token) {
    return { error: "Server misconfigured: missing CLAWHUB_TOKEN", status: 500 };
  }

  const clawhubUrl = `https://clawhub.ai/api/v1/skills/${encodeURIComponent(slug.trim())}`;

  for (let attempt = 0; attempt < 3; attempt++) {
    const resp = await fetch(clawhubUrl, {
      headers: {
        "User-Agent": "clawhub-skill-score-api/1.0",
        "Authorization": `Bearer ${token}`,
      },
    });

    if (resp.status === 429 && attempt < 2) {
      const retryAfter = parseInt(resp.headers.get("Retry-After") || "5", 10);
      await new Promise(r => setTimeout(r, retryAfter * 1000));
      continue;
    }

    if (!resp.ok) {
      const body = await resp.text();
      return { error: `ClawHub API error ${resp.status}: ${body}`, status: resp.status === 404 ? 404 : 502 };
    }

    const data = await resp.json();
    return { data, status: 200 };
  }

  return { error: "ClawHub API rate limited after retries", status: 429 };
}

// ── Download (proxy ClawHub download API) ───────────────────────────

export async function handleDownload(request, env) {
  if (request.method !== "GET") {
    return { error: "Method not allowed. Use GET.", status: 405 };
  }

  const url = new URL(request.url);
  const slug = url.searchParams.get("slug");
  if (!slug || !slug.trim()) {
    return { error: "Missing required parameter: slug", status: 400 };
  }

  const token = env.CLAWHUB_TOKEN;
  if (!token) {
    return { error: "Server misconfigured: missing CLAWHUB_TOKEN", status: 500 };
  }

  const clawhubUrl = new URL("https://clawhub.ai/api/download");
  clawhubUrl.searchParams.set("slug", slug.trim());

  const version = url.searchParams.get("version");
  if (version) clawhubUrl.searchParams.set("version", version);

  // Retry with backoff on 429
  for (let attempt = 0; attempt < 3; attempt++) {
    const resp = await fetch(clawhubUrl.toString(), {
      headers: {
        "User-Agent": "clawhub-skill-score-api/1.0",
        "Authorization": `Bearer ${token}`,
      },
    });

    if (resp.status === 429 && attempt < 2) {
      const retryAfter = parseInt(resp.headers.get("Retry-After") || "5", 10);
      await new Promise(r => setTimeout(r, retryAfter * 1000));
      continue;
    }

    if (!resp.ok) {
      const body = await resp.text();
      return { error: `ClawHub API error ${resp.status}: ${body}`, status: resp.status === 404 ? 404 : 502 };
    }

    // Return ZIP directly as binary response
    const zipData = await resp.arrayBuffer();
    return {
      raw: new Response(zipData, {
        status: 200,
        headers: {
          "Content-Type": "application/zip",
          "Content-Disposition": `attachment; filename="${slug.trim()}.zip"`,
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      }),
    };
  }

  return { error: "ClawHub API rate limited after retries", status: 429 };
}

// ── Search (proxy to ClawHub API) ───────────────────────────────────

export async function handleSearch(request, env) {
  if (request.method !== "GET") {
    return { error: "Method not allowed. Use GET.", status: 405 };
  }

  const url = new URL(request.url);
  const q = url.searchParams.get("q");
  if (!q || !q.trim()) {
    return { error: "Missing required parameter: q", status: 400 };
  }

  const token = env.CLAWHUB_TOKEN;
  if (!token) {
    return { error: "Server misconfigured: missing CLAWHUB_TOKEN", status: 500 };
  }

  // Build ClawHub API URL
  const params = new URLSearchParams({ q: q.trim() });

  const limit = url.searchParams.get("limit");
  {
    const n = limit ? parseInt(limit, 10) : 25;
    if (isNaN(n) || n < 1) return { error: "limit must be a positive integer", status: 400 };
    params.set("limit", String(Math.min(n, 50)));
  }

  const highlightedOnly = url.searchParams.get("highlightedOnly");
  if (highlightedOnly === "true" || highlightedOnly === "1") params.set("highlightedOnly", "true");

  const nonSuspiciousOnly = url.searchParams.get("nonSuspiciousOnly");
  if (nonSuspiciousOnly === "true" || nonSuspiciousOnly === "1") params.set("nonSuspiciousOnly", "true");

  const clawhubUrl = `https://clawhub.ai/api/v1/search?${params.toString()}`;

  // Retry with backoff on 429
  for (let attempt = 0; attempt < 3; attempt++) {
    const resp = await fetch(clawhubUrl, {
      headers: {
        "User-Agent": "clawhub-skill-score-api/1.0",
        "Authorization": `Bearer ${token}`,
      },
    });

    if (resp.status === 429 && attempt < 2) {
      const retryAfter = parseInt(resp.headers.get("Retry-After") || "5", 10);
      await new Promise(r => setTimeout(r, retryAfter * 1000));
      continue;
    }

    if (!resp.ok) {
      const body = await resp.text();
      return { error: `ClawHub API error ${resp.status}: ${body}`, status: 502 };
    }

    const data = await resp.json();
    return { data, status: 200 };
  }

  return { error: "ClawHub API rate limited after retries", status: 429 };
}

// ── Service info ────────────────────────────────────────────────────

export function handleServiceInfo() {
  return {
    service: "clawhub-skill-score",
    version: "v1",
    description: "ClawHub skill search and scoring API.",
    endpoints: [
      {
        method: "GET",
        path: "/clawhub-skill-score/v1/search",
        params: {
          q: { type: "string", required: true, description: "Search query" },
          limit: { type: "number", required: false, description: "Max results" },
          highlightedOnly: { type: "boolean", required: false, description: "Filter to highlighted skills only" },
          nonSuspiciousOnly: { type: "boolean", required: false, description: "Filter out suspicious skills" },
        },
      },
      {
        method: "GET",
        path: "/clawhub-skill-score/v1/download",
        description: "Download a skill as ZIP",
        params: {
          slug: { type: "string", required: true, description: "Skill slug" },
          version: { type: "string", required: false, description: "Specific version" },
        },
      },
      {
        method: "POST",
        path: "/clawhub-skill-score/v1/score",
        contentType: "multipart/form-data",
        fields: {
          query: { type: "string", required: true, description: "Search query" },
          skill: { type: "file (zip)", required: true, description: "Skill folder as ZIP" },
          slug: { type: "string", required: false, description: "Override slug (default: zip root dir name)" },
          displayName: { type: "string", required: false, description: "Override display name" },
          downloads: { type: "number", required: false, description: "Download count (default: 0)" },
        },
      },
    ],
  };
}
