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
 */
function parseZip(buffer) {
  const view = new DataView(buffer);
  const entries = [];
  let offset = 0;

  while (offset < buffer.byteLength - 4) {
    const sig = view.getUint32(offset, true);
    if (sig !== 0x04034b50) break; // Local file header signature

    const method = view.getUint16(offset + 8, true);
    const compressedSize = view.getUint32(offset + 18, true);
    const uncompressedSize = view.getUint32(offset + 22, true);
    const nameLen = view.getUint16(offset + 26, true);
    const extraLen = view.getUint16(offset + 28, true);
    const nameBytes = new Uint8Array(buffer, offset + 30, nameLen);
    const name = new TextDecoder().decode(nameBytes);
    const dataOffset = offset + 30 + nameLen + extraLen;
    const rawData = new Uint8Array(buffer, dataOffset, compressedSize);

    if (!name.endsWith("/")) {
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

    offset = dataOffset + compressedSize;
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

  // Find zip root directory (strip common prefix)
  let rootDir = "";
  const firstSlash = files[0]?.name?.indexOf("/");
  if (firstSlash > 0) {
    const prefix = files[0].name.slice(0, firstSlash + 1);
    if (files.every(f => f.name.startsWith(prefix))) {
      rootDir = prefix.slice(0, -1); // directory name without trailing /
    }
  }

  // Normalize paths (strip root prefix)
  const normalize = (name) => rootDir ? name.slice(rootDir.length + 1) : name;

  // Find SKILL.md
  const skillMdEntry = files.find(f => {
    const rel = normalize(f.name);
    return rel === "SKILL.md" || rel.toLowerCase() === "skill.md";
  });
  if (!skillMdEntry) {
    throw new Error("SKILL.md not found in ZIP");
  }

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
    if (!rel || rel === "SKILL.md") continue;

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
    },
  };
}

function round4(n) {
  return Math.round(n * 10000) / 10000;
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

  let formData;
  try {
    formData = await request.formData();
  } catch (e) {
    return { error: `Failed to parse form data: ${e.message}`, status: 400 };
  }

  const query = formData.get("query");
  if (!query || typeof query !== "string" || !query.trim()) {
    return { error: "Missing required field: query", status: 400 };
  }

  const skillFile = formData.get("skill");
  if (!skillFile) {
    const keys = [];
    for (const [k, v] of formData.entries()) {
      keys.push(`${k}: type=${typeof v} ctor=${v?.constructor?.name ?? "?"} size=${v?.size ?? "N/A"}`);
    }
    return { error: `Missing 'skill' field. Found fields: [${keys.join("; ")}]`, status: 400 };
  }

  // In Workers, file uploads come as File (or Blob) objects, not strings
  let zipBuffer;
  if (typeof skillFile === "string") {
    return { error: `skill field is a string (length=${skillFile.length}). Expected file upload. Make sure to use -F "skill=@file.zip"`, status: 400 };
  }
  try {
    zipBuffer = await skillFile.arrayBuffer();
  } catch (e) {
    return { error: `Failed to read skill file: ${e.message}. Type: ${typeof skillFile}, ctor: ${skillFile?.constructor?.name}`, status: 400 };
  }

  // Optional overrides
  const slug = formData.get("slug") || undefined;
  const displayName = formData.get("displayName") || undefined;
  const downloadsStr = formData.get("downloads");
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

// ── Service info ────────────────────────────────────────────────────

export function handleServiceInfo() {
  return {
    service: "clawhub-skill-score",
    version: "v1",
    description: "Score a skill against a ClawHub search query. Replicates ClawHub's exact scoring pipeline.",
    endpoints: [
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
