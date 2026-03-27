/**
 * oc-skill-scanner — OpenClaw Skill Security Scanner API
 *
 * Replicates ClawHub's OpenClaw moderation pipeline:
 *   1. Static regex scan (moderationEngine)
 *   2. LLM security evaluation (gpt-5-mini via Azure OpenAI)
 *   3. Combined verdict
 *
 * Endpoints:
 *   POST /scan   — Upload skill ZIP, run full security evaluation
 */

// ── Reason codes (from ClawHub moderationReasonCodes.ts) ────────────

const REASON_CODES = {
  DANGEROUS_EXEC: "suspicious.dangerous_exec",
  DYNAMIC_CODE: "suspicious.dynamic_code",
  CRYPTO_MINING: "malicious.crypto_mining",
  SUSPICIOUS_NETWORK: "suspicious.suspicious_network",
  EXFILTRATION: "suspicious.exfiltration",
  CREDENTIAL_HARVEST: "malicious.credential_harvest",
  OBFUSCATED_CODE: "suspicious.obfuscated_code",
  MALICIOUS_INSTALL_PROMPT: "malicious.malicious_install_prompt",
  INJECTION_INSTRUCTIONS: "suspicious.injection_instructions",
  SUSPICIOUS_INSTALL_SOURCE: "suspicious.suspicious_install_source",
  MANIFEST_PRIVILEGED_ALWAYS: "suspicious.manifest_privileged_always",
  KNOWN_BLOCKED_SIGNATURE: "malicious.known_blocked_signature",
};

// ── Static scan (from ClawHub moderationEngine.ts) ──────────────────

const CODE_EXT = /\.(js|ts|mjs|cjs|mts|cts|jsx|tsx|py|sh|bash|zsh|rb|go)$/i;
const MARKDOWN_EXT = /\.(md|markdown|mdx)$/i;
const MANIFEST_EXT = /\.(json|yaml|yml|toml)$/i;
const RAW_IP_URL = /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:\/|["'])/i;

function findFirstLine(content, pattern) {
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) return { line: i + 1, text: lines[i].slice(0, 160) };
  }
  return { line: 1, text: (lines[0] || "").slice(0, 160) };
}

function runStaticScan(files) {
  const findings = [];

  for (const { path, content } of files) {
    // Code files
    if (CODE_EXT.test(path)) {
      if (/child_process/.test(content) && /\b(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(/.test(content)) {
        const m = findFirstLine(content, /\b(exec|execSync|spawn|spawnSync)\s*\(/);
        findings.push({ code: REASON_CODES.DANGEROUS_EXEC, severity: "critical", file: path, line: m.line, message: "Shell command execution detected (child_process).", evidence: m.text });
      }
      if (/\beval\s*\(|new\s+Function\s*\(/.test(content)) {
        const m = findFirstLine(content, /\beval\s*\(|new\s+Function\s*\(/);
        findings.push({ code: REASON_CODES.DYNAMIC_CODE, severity: "critical", file: path, line: m.line, message: "Dynamic code execution detected.", evidence: m.text });
      }
      if (/stratum\+tcp|stratum\+ssl|coinhive|cryptonight|xmrig/i.test(content)) {
        const m = findFirstLine(content, /stratum\+tcp|stratum\+ssl|coinhive|cryptonight|xmrig/i);
        findings.push({ code: REASON_CODES.CRYPTO_MINING, severity: "critical", file: path, line: m.line, message: "Possible crypto mining behavior detected.", evidence: m.text });
      }
      const wsMatch = content.match(/new\s+WebSocket\s*\(\s*["']wss?:\/\/[^"']*:(\d+)/);
      if (wsMatch) {
        const port = parseInt(wsMatch[1], 10);
        if (port && ![80, 443, 8080, 8443, 3000].includes(port)) {
          const m = findFirstLine(content, /new\s+WebSocket\s*\(/);
          findings.push({ code: REASON_CODES.SUSPICIOUS_NETWORK, severity: "warn", file: path, line: m.line, message: "WebSocket connection to non-standard port.", evidence: m.text });
        }
      }
      if (/readFileSync|readFile/.test(content) && /\bfetch\b|http\.request|\baxios\b/.test(content)) {
        const m = findFirstLine(content, /readFileSync|readFile/);
        findings.push({ code: REASON_CODES.EXFILTRATION, severity: "warn", file: path, line: m.line, message: "File read combined with network send (possible exfiltration).", evidence: m.text });
      }
      if (/process\.env/.test(content) && /\bfetch\b|http\.request|\baxios\b/.test(content)) {
        const m = findFirstLine(content, /process\.env/);
        findings.push({ code: REASON_CODES.CREDENTIAL_HARVEST, severity: "critical", file: path, line: m.line, message: "Environment variable access combined with network send.", evidence: m.text });
      }
      if (/(\\x[0-9a-fA-F]{2}){6,}/.test(content) || /(?:atob|Buffer\.from)\s*\(\s*["'][A-Za-z0-9+/=]{200,}["']/.test(content)) {
        const m = findFirstLine(content, /(\\x[0-9a-fA-F]{2}){6,}|(?:atob|Buffer\.from)\s*\(/);
        findings.push({ code: REASON_CODES.OBFUSCATED_CODE, severity: "warn", file: path, line: m.line, message: "Potential obfuscated payload detected.", evidence: m.text });
      }
    }

    // Markdown files
    if (MARKDOWN_EXT.test(path)) {
      if (/ignore\s+(all\s+)?previous\s+instructions/i.test(content) || /system\s*prompt\s*[:=]/i.test(content)) {
        const m = findFirstLine(content, /ignore\s+(all\s+)?previous\s+instructions|system\s*prompt\s*[:=]/i);
        findings.push({ code: REASON_CODES.INJECTION_INSTRUCTIONS, severity: "warn", file: path, line: m.line, message: "Prompt-injection style instruction pattern detected.", evidence: m.text });
      }
    }

    // Manifest files
    if (MANIFEST_EXT.test(path)) {
      if (/https?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd)\//i.test(content) || RAW_IP_URL.test(content)) {
        const m = findFirstLine(content, /https?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd)\/|https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/i);
        findings.push({ code: REASON_CODES.SUSPICIOUS_INSTALL_SOURCE, severity: "warn", file: path, line: m.line, message: "Install source points to URL shortener or raw IP.", evidence: m.text });
      }
    }
  }

  // Dedupe
  const seen = new Set();
  const deduped = [];
  for (const f of findings) {
    const key = `${f.code}:${f.file}:${f.line}`;
    if (!seen.has(key)) { seen.add(key); deduped.push(f); }
  }

  const codes = [...new Set(deduped.map(f => f.code))];
  let verdict = "clean";
  if (codes.some(c => c.startsWith("malicious."))) verdict = "malicious";
  else if (codes.length > 0) verdict = "suspicious";

  return { verdict, reasonCodes: codes, findings: deduped.slice(0, 40) };
}

// ── Frontmatter parser ──────────────────────────────────────────────

function parseFrontmatter(content) {
  const match = content.match(/^---\n([\s\S]*?)\n---/);
  if (!match) return { fm: {}, body: content };

  const fm = {};
  let currentKey = null;
  let currentValue = "";
  let isMultiline = false;

  for (const line of match[1].split("\n")) {
    if (isMultiline) {
      if (/^\S/.test(line) && /^[a-zA-Z]/.test(line) && line.includes(":")) {
        fm[currentKey] = currentValue.trim();
        isMultiline = false;
      } else {
        currentValue += " " + line.trim();
        continue;
      }
    }
    const kv = line.match(/^([a-zA-Z_-]+)\s*:\s*(>-?|.*)/);
    if (kv) {
      currentKey = kv[1];
      if (kv[2] === ">" || kv[2] === ">-") {
        currentValue = "";
        isMultiline = true;
      } else {
        fm[currentKey] = kv[2].trim().replace(/^["']|["']$/g, "");
      }
    }
  }
  if (isMultiline && currentKey) fm[currentKey] = currentValue.trim();

  return { fm, body: content.slice(match[0].length) };
}

// ── LLM Security Evaluation ─────────────────────────────────────────

const MAX_SKILL_MD_CHARS = 6000;
const MAX_FILE_CHARS = 10000;
const MAX_TOTAL_FILE_CHARS = 50000;

// System prompt from ClawHub securityPrompt.ts (abbreviated to key sections)
const SYSTEM_PROMPT = `You are a security evaluator for OpenClaw AI skills. Users install skills to extend what their AI agent can do.

You are not a malware classifier. You are an incoherence detector.

Assess the skill across five dimensions:
1. Purpose–capability alignment — do requirements match the stated purpose?
2. Instruction scope — do SKILL.md instructions stay within boundaries?
3. Install mechanism risk — what does the skill install and how?
4. Environment and credential proportionality — are secrets proportionate?
5. Persistence and privilege — what system presence is requested?

Verdict definitions:
- benign: Internally consistent with stated purpose.
- suspicious: Inconsistencies that could be legitimate or not.
- malicious: Fundamentally incompatible with stated purpose across multiple dimensions.

When in doubt between benign and suspicious, choose suspicious.
When in doubt between suspicious and malicious, choose suspicious.
NEVER classify as malicious solely because it uses shell execution, network calls, or file I/O.

Respond with a JSON object:
{
  "verdict": "benign" | "suspicious" | "malicious",
  "confidence": "high" | "medium" | "low",
  "summary": "One sentence a non-technical user can understand.",
  "dimensions": {
    "purpose_capability": { "status": "ok" | "note" | "concern", "detail": "..." },
    "instruction_scope": { "status": "ok" | "note" | "concern", "detail": "..." },
    "install_mechanism": { "status": "ok" | "note" | "concern", "detail": "..." },
    "environment_proportionality": { "status": "ok" | "note" | "concern", "detail": "..." },
    "persistence_privilege": { "status": "ok" | "note" | "concern", "detail": "..." }
  },
  "user_guidance": "Plain-language explanation of what to consider before installing."
}`;

function assembleEvalMessage(skillMdContent, files, staticFindings) {
  const { fm } = parseFrontmatter(skillMdContent);
  const skillMd = skillMdContent.length > MAX_SKILL_MD_CHARS
    ? skillMdContent.slice(0, MAX_SKILL_MD_CHARS) + "\n…[truncated]"
    : skillMdContent;

  const codeExts = new Set([".js",".ts",".mjs",".cjs",".jsx",".tsx",".py",".rb",".sh",".bash",".go",".rs"]);
  const codeFiles = files.filter(f => {
    const ext = f.path.slice(f.path.lastIndexOf(".")).toLowerCase();
    return codeExts.has(ext);
  });

  let sections = [];
  sections.push(`## Skill under evaluation
**Name:** ${fm.name || "unknown"}
**Description:** ${fm.description || "No description"}
**Keywords:** ${fm.keywords || "none"}

### Requirements
- Env vars: ${fm.requires || "none declared"}
- Primary credential: ${fm.primaryCredential || fm.primaryEnv || "none"}

### File manifest
${files.map(f => `  ${f.path}`).join("\n")}

### Code files
${codeFiles.length ? codeFiles.map(f => `  ${f.path}`).join("\n") : "No code files (instruction-only skill)"}

### Static scan findings
${staticFindings.length ? staticFindings.map(f => `- [${f.severity}] ${f.file}:${f.line} — ${f.message}`).join("\n") : "None detected."}

### SKILL.md content
${skillMd}`);

  // Add file contents
  let totalChars = 0;
  const fileBlocks = [];
  for (const f of files) {
    if (totalChars >= MAX_TOTAL_FILE_CHARS) break;
    const content = f.content.length > MAX_FILE_CHARS
      ? f.content.slice(0, MAX_FILE_CHARS) + "\n…[truncated]"
      : f.content;
    fileBlocks.push(`#### ${f.path}\n\`\`\`\n${content}\n\`\`\``);
    totalChars += content.length;
  }
  if (fileBlocks.length > 0) {
    sections.push(`### File contents\n${fileBlocks.join("\n\n")}`);
  }

  sections.push("Respond with your evaluation as a single JSON object.");
  return sections.join("\n\n");
}

async function runLlmEval(userMessage, env) {
  const baseUrl = env.AZURE_CHAT_URL || env.EMBED_BASE_URL?.replace(/\/deployments\/[^/]+\/embeddings/, "/deployments/gpt-5-mini/chat/completions");
  const apiKey = env.AZURE_CHAT_KEY || env.EMBED_API_KEY;

  if (!baseUrl || !apiKey) {
    return { error: "LLM eval not configured" };
  }

  const url = baseUrl.includes("?") ? baseUrl : baseUrl + "?api-version=2025-01-01-preview";

  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "api-key": apiKey },
    body: JSON.stringify({
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: userMessage },
      ],
      max_completion_tokens: 4000,
      response_format: { type: "json_object" },
    }),
  });

  if (!resp.ok) {
    const text = await resp.text();
    return { error: `LLM API ${resp.status}: ${text}` };
  }

  const data = await resp.json();
  const content = data.choices?.[0]?.message?.content;
  if (!content) return { error: "Empty LLM response" };

  try {
    return { result: JSON.parse(content), usage: data.usage };
  } catch {
    return { error: "Failed to parse LLM JSON response", raw: content };
  }
}

// ── Combined verdict ────────────────────────────────────────────────

function combineVerdicts(staticVerdict, llmVerdict) {
  if (staticVerdict === "malicious" || llmVerdict === "malicious") return "malicious";
  if (staticVerdict === "suspicious" || llmVerdict === "suspicious") return "suspicious";
  return "clean";
}

// ── Handlers ────────────────────────────────────────────────────────

export async function handleOcScan(request, env, parseZipFn) {
  if (request.method !== "POST") {
    return { error: "Method not allowed. Use POST with multipart/form-data.", status: 405 };
  }

  const contentType = request.headers.get("content-type") || "";
  if (!contentType.includes("multipart/form-data")) {
    return { error: "Content-Type must be multipart/form-data", status: 400 };
  }

  const body = await request.arrayBuffer();
  const { files: uploadedFiles } = parseZipFn.parseMultipart(body, contentType);
  const zipBytes = uploadedFiles.skill;

  if (!zipBytes || zipBytes.length === 0) {
    return { error: "Missing required field: skill (ZIP file)", status: 400 };
  }

  if (zipBytes.length > 5 * 1024 * 1024) {
    return { error: "ZIP file too large (max 5MB)", status: 413 };
  }

  try {
    const rawFiles = await parseZipFn.parseZip(zipBytes);
    const entries = parseZipFn.normalizeEntries(rawFiles);
    if (entries.length === 0) {
      return { error: "No valid skill files found in ZIP", status: 400 };
    }

    // Decode file contents
    const textDecoder = new TextDecoder();
    const textFiles = entries.map(e => ({
      path: e.path,
      content: textDecoder.decode(e.bytes),
    }));

    // Find SKILL.md
    const skillMd = textFiles.find(f => f.path.toLowerCase() === "skill.md");
    if (!skillMd) {
      return { error: "SKILL.md not found in ZIP", status: 400 };
    }

    // Step 1: Static scan
    const staticScan = runStaticScan(textFiles);

    // Step 2: LLM eval
    const evalMessage = assembleEvalMessage(skillMd.content, textFiles, staticScan.findings);
    const llmResult = await runLlmEval(evalMessage, env);

    // Step 3: Combine
    const llmVerdict = llmResult.result?.verdict || "unknown";
    const combinedVerdict = llmResult.error ? staticScan.verdict : combineVerdicts(staticScan.verdict, llmVerdict);

    return {
      data: {
        verdict: combinedVerdict,
        staticScan: {
          verdict: staticScan.verdict,
          reasonCodes: staticScan.reasonCodes,
          findings: staticScan.findings,
        },
        llmEval: llmResult.error
          ? { error: llmResult.error }
          : {
              verdict: llmResult.result.verdict,
              confidence: llmResult.result.confidence,
              summary: llmResult.result.summary,
              dimensions: llmResult.result.dimensions,
              guidance: llmResult.result.user_guidance,
            },
        files: entries.length,
        usage: llmResult.usage || null,
      },
      status: 200,
    };
  } catch (e) {
    return { error: e.message, status: 422 };
  }
}

export function handleOcScannerInfo() {
  return {
    service: "oc-skill-scanner",
    version: "v1",
    endpoints: [
      { method: "POST", path: "/oc-skill-scanner/v1/scan", description: "Upload skill ZIP for OpenClaw security evaluation (static scan + LLM eval)" },
    ],
  };
}
