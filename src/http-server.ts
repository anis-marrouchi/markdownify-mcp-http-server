/* ---------------------------------------------------------------
 * markdownify MCP server with:
 *  - StdIO MCP (createServer)
 *  - REST API (Hono)
 *  - SSE MCP transport (GET /sse, POST /messages)
 *  - Streamable HTTP MCP transport (POST /mcp)
 *  - File upload & auto-conversion
 *  - Sandbox & safety checks
 * --------------------------------------------------------------- */

import { z } from "zod";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { CallToolRequest } from "@modelcontextprotocol/sdk/types.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";

import { Markdownify } from "./Markdownify.js";
import * as tools from "./tools.js";
import is_ip_private from "private-ip";
import { URL } from "node:url";

import { Hono } from "hono";
import http from "node:http";

import Busboy from "busboy";
import {
  mkdir,
  stat,
  readdir,
  unlink,
  realpath,
  access,
} from "node:fs/promises";
import { createWriteStream } from "node:fs";
import { randomBytes, createHash, randomUUID } from "node:crypto";
import { basename, extname, join } from "node:path";

/* -------------------- Original MCP stdio server -------------------- */

const RequestPayloadSchema = z.object({
  filepath: z.string().optional(),
  url: z.string().optional(),
  projectRoot: z.string().optional(),
  uvPath: z.string().optional(),
  tool_type: z.string().optional(),
  instructions: z.boolean().optional(),
});

export function createServer() {
  const server = new Server(
    {
      name: "mcp-markdownify-server",
      version: "0.1.0",
    },
    {
      capabilities: { tools: {} },
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools: Object.values(tools) };
  });

  server.setRequestHandler(
    CallToolRequestSchema,
    async (request: CallToolRequest) => {
      const { name, arguments: args } = request.params;
      const validatedArgs = RequestPayloadSchema.parse(args);

      try {
        let result;
        switch (name) {
          case tools.YouTubeToMarkdownTool.name:
          case tools.BingSearchResultToMarkdownTool.name:
          case tools.WebpageToMarkdownTool.name: {
            if (!validatedArgs.url) throw new Error("URL is required");
            const parsedUrl = new URL(validatedArgs.url);
            if (!["http:", "https:"].includes(parsedUrl.protocol))
              throw new Error("Only http/https URLs allowed.");
            if (is_ip_private(parsedUrl.hostname))
              throw new Error(
                `Fetching ${validatedArgs.url} is potentially dangerous.`,
              );
            result = await Markdownify.toMarkdown({
              url: validatedArgs.url,
              projectRoot: validatedArgs.projectRoot,
              uvPath: validatedArgs.uvPath || process.env.UV_PATH,
            });
            break;
          }
          case tools.PDFToMarkdownTool.name:
          case tools.ImageToMarkdownTool.name:
          case tools.AudioToMarkdownTool.name:
          case tools.DocxToMarkdownTool.name:
          case tools.XlsxToMarkdownTool.name:
          case tools.PptxToMarkdownTool.name: {
            if (!validatedArgs.filepath) throw new Error("File path is required");
            result = await Markdownify.toMarkdown({
              filePath: validatedArgs.filepath,
              projectRoot: validatedArgs.projectRoot,
              uvPath: validatedArgs.uvPath || process.env.UV_PATH,
            });
            break;
          }
          case tools.GetMarkdownFileTool.name: {
            if (!validatedArgs.filepath) throw new Error("File path is required");
            result = await Markdownify.get({ filePath: validatedArgs.filepath });
            break;
          }
          case tools.UploadAndConvertTool.name: {
            const { tool_type } = validatedArgs as any;
            if (!tool_type) throw new Error("tool_type is required");
            
            const uploadInstructions = `
# File Upload Instructions

To upload and convert files when using the remote server (https://markdownify.mcp.noqta.tn/):

## Method 1: Upload and Convert in One Step
\`\`\`bash
curl -X POST https://markdownify.mcp.noqta.tn/upload-and-convert?tool=${tool_type} \\
  -H "Content-Type: multipart/form-data" \\
  -F "file=@/path/to/your/file"
\`\`\`

## Method 2: Upload First, Then Convert
1. **Upload the file:**
\`\`\`bash
curl -X POST https://markdownify.mcp.noqta.tn/upload \\
  -H "Content-Type: multipart/form-data" \\
  -F "file=@/path/to/your/file"
\`\`\`

2. **Use the returned filepath with the MCP tool:**
Use the \`filepath\` from the upload response in your MCP tool call.

## Method 3: Use URL (for files already online)
If your file is already accessible via URL, use the \`url\` parameter directly:
\`\`\`json
{
  "name": "${tool_type}",
  "arguments": {
    "url": "https://example.com/your-file.pdf"
  }
}
\`\`\`

## Supported File Types
- PDF files (.pdf)
- Image files (.jpg, .jpeg, .png, .gif, .bmp, .webp)
- Audio files (.mp3, .wav, .m4a, .flac, .aac)
- Document files (.docx, .xlsx, .pptx)

## Upload Limits
- Maximum file size: ${Math.round(MAX_UPLOAD_BYTES / (1024 * 1024))}MB
- Files are automatically cleaned up after ${Math.round(UPLOAD_TTL_MS / (60 * 60 * 1000))} hour(s)
`;

            result = {
              path: "upload-instructions.md",
              text: uploadInstructions,
            };
            break;
          }
          default:
            throw new Error("Tool not found");
        }

        return {
          content: [
            { type: "text", text: `Output file: ${result.path}` },
            { type: "text", text: "Converted content:" },
            { type: "text", text: result.text },
          ],
          isError: false,
        };
      } catch (e) {
        if (e instanceof Error) {
          return {
            content: [{ type: "text", text: `Error: ${e.message}` }],
            isError: true,
          };
        }
        console.error(e);
        return {
            content: [{ type: "text", text: "Error: Unknown error occurred" }],
            isError: true,
        };
      }
    },
  );

  return server;
}

/* -------------------- Environment & Config -------------------- */

const ENABLE_HTTP = true;
const ENABLE_SSE = true;
const ENABLE_STREAMABLE_HTTP = true;
const PORT = Number(process.env.PORT || 3100);

const UPLOAD_ROOT = process.env.MD_SHARE_DIR || join(process.cwd(), "uploads");
const ENFORCE_SHARE_DIR = !!process.env.MD_SHARE_DIR;

const MAX_UPLOAD_BYTES = Number(process.env.MAX_UPLOAD_BYTES || 50 * 1024 * 1024);
const UPLOAD_TTL_MS = Number(process.env.UPLOAD_TTL_MS || 60 * 60 * 1000);
const CLEAN_INTERVAL_MS = Number(process.env.CLEAN_INTERVAL_MS || 30 * 60 * 1000);

const ALLOWED_EXTENSIONS = (process.env.ALLOWED_EXTENSIONS || "")
  .split(",")
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

const UV_PATH = process.env.UV_PATH;
const MCP_HTTP_TOKEN = process.env.MCP_HTTP_TOKEN || "";
const MCP_SSE_PATH = process.env.MCP_SSE_PATH || "/sse";
const MCP_MESSAGES_PATH = process.env.MCP_MESSAGES_PATH || "/messages";
const MCP_STREAMABLE_HTTP_PATH = process.env.MCP_STREAMABLE_HTTP_PATH || "/mcp";

const PROTOCOL_VERSION = "2024-11-0";

const TOKEN_HEADER_ALIASES = ["x-mcp-token", "x-mcp-api-key", "x-mcp-key"];

function extractToken(headers: http.IncomingHttpHeaders) {
  for (const key of TOKEN_HEADER_ALIASES) {
    const v = headers[key];
    if (v) return Array.isArray(v) ? v[0] : v;
  }
  return "";
}

function log(...a: any[]) {
  // Use stderr to avoid polluting stdio JSON-RPC
  console.error("[HTTP]", ...a);
}

/* -------------------- Utilities -------------------- */

async function ensureDir(d: string) {
  try { await stat(d); } catch { await mkdir(d, { recursive: true }); }
}

function randomFileName(ext: string) {
  return randomBytes(16).toString("hex") + ext.toLowerCase();
}

function isAllowedExtension(ext: string) {
  if (!ALLOWED_EXTENSIONS.length) return true;
  return ALLOWED_EXTENSIONS.includes(ext.toLowerCase());
}

async function sandboxFilePath(p?: string) {
  if (!p) throw new Error("filepath is required");
  if (!ENFORCE_SHARE_DIR) return p;
  const real = await realpath(p);
  const base = await realpath(UPLOAD_ROOT);
  if (!real.startsWith(base)) {
    throw new Error("File path outside allowed directory");
  }
  return real;
}

async function saveStreamToFile(opts: {
  stream: NodeJS.ReadableStream;
  originalName: string;
  uploadDir: string;
  maxBytes: number;
}) {
  await ensureDir(opts.uploadDir);
  const ext = extname(opts.originalName) || "";
  if (!isAllowedExtension(ext)) {
    throw new Error(
      `Extension "${ext || "(none)"}" not allowed. Allowed: ${
        ALLOWED_EXTENSIONS.length ? ALLOWED_EXTENSIONS.join(",") : "any"
      }`,
    );
  }

  const finalName = randomFileName(ext);
  const absolutePath = join(opts.uploadDir, finalName);
  let size = 0;
  const sha = createHash("sha256");

  await new Promise<void>((resolve, reject) => {
    const ws = createWriteStream(absolutePath, { flags: "wx" });
    opts.stream.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > opts.maxBytes) {
        ws.destroy();
        reject(new Error("File too large"));
        return;
      }
      sha.update(chunk);
      ws.write(chunk);
    });
    opts.stream.on("end", () => ws.end());
    ws.on("close", resolve);
    ws.on("error", reject);
    opts.stream.on("error", reject);
  });

  return {
    absolutePath,
    originalName: basename(opts.originalName),
    size,
    sha256: sha.digest("hex"),
    ext,
  };
}

/* -------------------- Tool classification -------------------- */
const URL_TOOL_SET = new Set([
  tools.YouTubeToMarkdownTool.name,
  tools.BingSearchResultToMarkdownTool.name,
  tools.WebpageToMarkdownTool.name,
]);
const FILE_TOOL_SET = new Set([
  tools.PDFToMarkdownTool.name,
  tools.ImageToMarkdownTool.name,
  tools.AudioToMarkdownTool.name,
  tools.DocxToMarkdownTool.name,
  tools.XlsxToMarkdownTool.name,
  tools.PptxToMarkdownTool.name,
]);
const GET_TOOL = tools.GetMarkdownFileTool.name;
const TOOL_NAMES = Object.values(tools).map(t => t.name);

/* -------------------- Conversion logic -------------------- */
async function runConversion(
  toolName: string,
  { filepath, url }: { filepath?: string; url?: string },
) {
  if (!TOOL_NAMES.includes(toolName)) throw new Error(`unknown tool "${toolName}"`);

  if (URL_TOOL_SET.has(toolName)) {
    if (!url) throw new Error("url is required");
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol))
      throw new Error("Only http/https URLs allowed");
    if (is_ip_private(parsed.hostname))
      throw new Error(`Fetching ${url} is potentially dangerous`);
    const r = await Markdownify.toMarkdown({ url, uvPath: UV_PATH });
    return r.text;
  }

  if (FILE_TOOL_SET.has(toolName)) {
    if (!filepath) throw new Error("filepath is required");
    const fp = await sandboxFilePath(filepath);
    const r = await Markdownify.toMarkdown({ filePath: fp, uvPath: UV_PATH });
    return r.text;
  }

  if (toolName === GET_TOOL) {
    if (!filepath) throw new Error("filepath is required");
    const fp = await sandboxFilePath(filepath);
    const lower = fp.toLowerCase();
    if (!lower.endsWith(".md") && !lower.endsWith(".markdown"))
      throw new Error("File is not markdown");
    const r = await Markdownify.get({ filePath: fp });
    return r.text;
  }

  throw new Error(`Unhandled tool "${toolName}"`);
}

/* -------------------- SSE Transport -------------------- */

// Store active SSE connections
const sseConnections = new Map<string, SSEServerTransport>();

/* -------------------- Streamable HTTP Transport -------------------- */

// Store active streamable HTTP sessions
const streamableHttpSessions = new Map<string, any>();

/* -------------------- Multipart Upload Handling -------------------- */

function handleMultipartUpload(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  autoConvert: boolean,
) {
  const contentType = req.headers["content-type"] || "";
  if (!contentType.startsWith("multipart/form-data")) {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Content-Type must be multipart/form-data" }));
    return;
  }

  const urlObj = new URL(req.url || "/", `http://${req.headers.host}`);
  const toolName = autoConvert
    ? urlObj.searchParams.get("tool") || tools.PDFToMarkdownTool.name
    : null;

  const busboy = Busboy({
    headers: { "content-type": contentType },
    limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 },
  });

  type SavedMeta = {
    absolutePath: string;
    originalName: string;
    size: number;
    sha256: string;
    ext: string;
  };
  let savedMeta: SavedMeta | null = null;
  let fileError: Error | null = null;
  const filePromises: Promise<void>[] = [];

  busboy.on("file", (_field, fileStream, info) => {
    const p = saveStreamToFile({
      stream: fileStream,
      originalName: info.filename,
      uploadDir: UPLOAD_ROOT,
      maxBytes: MAX_UPLOAD_BYTES,
    })
      .then(meta => { if (!savedMeta) savedMeta = meta; })
      .catch(err => {
        fileError = err instanceof Error ? err : new Error(String(err));
        fileStream.resume();
      });
    filePromises.push(p);
  });

  busboy.on("error", (err) => {
    fileError = err instanceof Error ? err : new Error(String(err));
  });

  busboy.on("finish", async () => {
    try {
      if (filePromises.length) await Promise.all(filePromises);
    } catch { /* ignore */ }

    if (fileError) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: fileError.message }));
      return;
    }
    if (!savedMeta) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "No file received" }));
      return;
    }
    if (!autoConvert) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        ok: true,
        filepath: savedMeta.absolutePath,
        size: savedMeta.size,
        sha256: savedMeta.sha256,
        originalName: savedMeta.originalName,
      }));
      return;
    }
    try {
      if (!toolName) throw new Error("tool not specified");
      const markdown = await runConversion(toolName, { filepath: savedMeta.absolutePath });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        ok: true,
        tool: toolName,
        filepath: savedMeta.absolutePath,
        markdown,
        size: savedMeta.size,
        sha256: savedMeta.sha256,
        originalName: savedMeta.originalName,
      }));
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: err.message }));
    }
  });

  req.pipe(busboy);
}

/* -------------------- Hono App (non-multipart JSON/GET) -------------------- */

const app = new Hono();

// Root listing
app.get("/", (c) => {
  if (!ENABLE_HTTP) return c.json({ error: "HTTP disabled" }, 404);
  return c.json({
    status: "ok",
    tools: TOOL_NAMES,
    uploadDir: UPLOAD_ROOT,
    maxUploadBytes: MAX_UPLOAD_BYTES,
    http: true,
    sse: ENABLE_SSE,
    streamableHttp: ENABLE_STREAMABLE_HTTP,
  });
});

// Health
app.get("/healthz", (c) =>
  c.json({
    ok: true,
    ts: Date.now(),
    sseConnections: sseConnections.size,
    streamableHttpSessions: streamableHttpSessions.size,
  }),
);

// Convert (JSON - not multipart)
app.post("/convert", async (c) => {
  if (!ENABLE_HTTP) return c.json({ error: "HTTP disabled" }, 404);
  try {
    const body = await c.req.json<{ tool: string; filepath?: string; url?: string }>();
    const { tool, filepath, url } = body;
    if (!tool) return c.json({ error: "tool is required" }, 400);
    const markdown = await runConversion(tool, { filepath, url });
    return c.json({ ok: true, tool, markdown });
  } catch (e: any) {
    return c.json({ error: e.message || "conversion error" }, 400);
  }
});

/* -------------------- Periodic Cleanup -------------------- */
setInterval(async () => {
  try {
    await ensureDir(UPLOAD_ROOT);
    const base = await realpath(UPLOAD_ROOT);
    const now = Date.now();
    const files = await readdir(base);
    for (const f of files) {
      const full = join(base, f);
      try {
        const s = await stat(full);
        if (now - s.mtimeMs > UPLOAD_TTL_MS) {
          await unlink(full);
        }
      } catch { /* ignore */ }
    }
  } catch { /* ignore */ }
}, CLEAN_INTERVAL_MS).unref();

/* -------------------- HTTP Server Wrapper -------------------- */

const server = http.createServer(async (req, res) => {
  try {
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-MCP-Session-ID');

    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }

    // Authentication check - only for MCP endpoints when token is configured
    const isMcpEndpoint = req.url?.startsWith(MCP_SSE_PATH) || 
                         req.url?.startsWith(MCP_MESSAGES_PATH) || 
                         req.url?.startsWith(MCP_STREAMABLE_HTTP_PATH);
    
    if (MCP_HTTP_TOKEN && isMcpEndpoint && extractToken(req.headers) !== MCP_HTTP_TOKEN) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "unauthorized" }));
      return;
    }

    // SSE endpoint
    if (ENABLE_SSE && req.method === "GET" && req.url?.startsWith(MCP_SSE_PATH)) {
      const transport = new SSEServerTransport(MCP_MESSAGES_PATH, res);
      const sessionId = transport.sessionId;
      
      log(`[SSE] New connection: ${sessionId}`);
      sseConnections.set(sessionId, transport);
      
      // Connect to MCP server
      const mcpServerInstance = createServer();
      await mcpServerInstance.connect(transport);
      
      // Handle connection close
      req.on('close', () => {
        log(`[SSE] Connection closed: ${sessionId}`);
        sseConnections.delete(sessionId);
      });
      
      return;
    }

    // SSE message endpoint
    if (ENABLE_SSE && req.method === "POST" && req.url?.startsWith(MCP_MESSAGES_PATH)) {
      const url = new URL(req.url || "/", `http://${req.headers.host}`);
      const sessionId = url.searchParams.get('sessionId') || req.headers['x-mcp-session-id'] as string;
      
      if (!sessionId || !sseConnections.has(sessionId)) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "invalid or missing sessionId" }));
        return;
      }
      
      const transport = sseConnections.get(sessionId)!;
      await transport.handlePostMessage(req, res);
      return;
    }

    // Streamable HTTP endpoint
    if (ENABLE_STREAMABLE_HTTP && req.method === "POST" && req.url?.startsWith(MCP_STREAMABLE_HTTP_PATH)) {
      const mcpServerInstance = createServer();
      
      // Handle the MCP request
      const body = await new Promise<Buffer>(resolve => {
        const chunks: Buffer[] = [];
        req.on("data", c => chunks.push(c));
        req.on("end", () => resolve(Buffer.concat(chunks)));
      });

      let requestData: any;
      try {
        requestData = JSON.parse(body.toString());
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "invalid json" }));
        return;
      }

      try {
        // Process the MCP request directly
        let result;
        const { method, id = null, params = {} } = requestData;

        switch (method) {
          case "initialize":
            result = {
              protocolVersion: PROTOCOL_VERSION,
              capabilities: { tools: {} },
              serverInfo: { name: "markdownify-mcp-streamable", version: "0.1.0" },
            };
            break;
          
          case "tools/list":
            result = { tools: Object.values(tools) };
            break;
          
          case "tools/call": {
            const { name, arguments: args } = params;
            if (!name) throw new Error("name is required");
            const validatedArgs = RequestPayloadSchema.parse(args || {});
            
            let conversionResult;
            switch (name) {
              case tools.YouTubeToMarkdownTool.name:
              case tools.BingSearchResultToMarkdownTool.name:
              case tools.WebpageToMarkdownTool.name: {
                if (!validatedArgs.url) throw new Error("URL is required");
                const parsedUrl = new URL(validatedArgs.url);
                if (!["http:", "https:"].includes(parsedUrl.protocol))
                  throw new Error("Only http/https allowed.");
                if (is_ip_private(parsedUrl.hostname))
                  throw new Error("Potentially dangerous URL (private IP)");
                conversionResult = await Markdownify.toMarkdown({
                  url: validatedArgs.url,
                  projectRoot: validatedArgs.projectRoot,
                  uvPath: validatedArgs.uvPath || process.env.UV_PATH,
                });
                break;
              }
          case tools.PDFToMarkdownTool.name:
          case tools.ImageToMarkdownTool.name:
          case tools.AudioToMarkdownTool.name:
          case tools.DocxToMarkdownTool.name:
          case tools.XlsxToMarkdownTool.name:
          case tools.PptxToMarkdownTool.name: {
            if (validatedArgs.url) {
              // Handle remote files via URL
              const parsedUrl = new URL(validatedArgs.url);
              if (!["http:", "https:"].includes(parsedUrl.protocol))
                throw new Error("Only http/https allowed.");
              if (is_ip_private(parsedUrl.hostname))
                throw new Error("Potentially dangerous URL (private IP)");
              conversionResult = await Markdownify.toMarkdown({
                url: validatedArgs.url,
                projectRoot: validatedArgs.projectRoot,
                uvPath: validatedArgs.uvPath || process.env.UV_PATH,
              });
            } else if (validatedArgs.filepath) {
              // Handle local files
              await sandboxFilePath(validatedArgs.filepath);
              conversionResult = await Markdownify.toMarkdown({
                filePath: validatedArgs.filepath,
                projectRoot: validatedArgs.projectRoot,
                uvPath: validatedArgs.uvPath || process.env.UV_PATH,
              });
            } else {
              throw new Error("Either filepath or url is required");
            }
            break;
          }
              case tools.GetMarkdownFileTool.name: {
                if (!validatedArgs.filepath) throw new Error("File path is required");
                await sandboxFilePath(validatedArgs.filepath);
                conversionResult = await Markdownify.get({ filePath: validatedArgs.filepath });
                break;
              }
              case tools.UploadAndConvertTool.name: {
                const { tool_type } = validatedArgs as any;
                if (!tool_type) throw new Error("tool_type is required");
                
                const uploadInstructions = `
# File Upload Instructions

To upload and convert files when using the remote server (https://markdownify.mcp.noqta.tn/):

## Method 1: Upload and Convert in One Step
\`\`\`bash
curl -X POST https://markdownify.mcp.noqta.tn/upload-and-convert?tool=${tool_type} \\
  -H "Content-Type: multipart/form-data" \\
  -F "file=@/path/to/your/file"
\`\`\`

## Method 2: Upload First, Then Convert
1. **Upload the file:**
\`\`\`bash
curl -X POST https://markdownify.mcp.noqta.tn/upload \\
  -H "Content-Type: multipart/form-data" \\
  -F "file=@/path/to/your/file"
\`\`\`

2. **Use the returned filepath with the MCP tool:**
Use the \`filepath\` from the upload response in your MCP tool call.

## Method 3: Use URL (for files already online)
If your file is already accessible via URL, use the \`url\` parameter directly:
\`\`\`json
{
  "name": "${tool_type}",
  "arguments": {
    "url": "https://example.com/your-file.pdf"
  }
}
\`\`\`

## Supported File Types
- PDF files (.pdf)
- Image files (.jpg, .jpeg, .png, .gif, .bmp, .webp)
- Audio files (.mp3, .wav, .m4a, .flac, .aac)
- Document files (.docx, .xlsx, .pptx)

## Upload Limits
- Maximum file size: ${Math.round(MAX_UPLOAD_BYTES / (1024 * 1024))}MB
- Files are automatically cleaned up after ${Math.round(UPLOAD_TTL_MS / (60 * 60 * 1000))} hour(s)
`;

                conversionResult = {
                  path: "upload-instructions.md",
                  text: uploadInstructions,
                };
                break;
              }
              default:
                throw new Error("Tool not found");
            }
            
            result = {
              content: [
                { type: "text", text: `Output file: ${conversionResult.path}` },
                { type: "text", text: "Converted content:" },
                { type: "text", text: conversionResult.text },
              ],
              isError: false,
            };
            break;
          }
          
          default:
            throw new Error(`Method ${method} not found`);
        }
        
        res.writeHead(200, { 
          "Content-Type": "application/json",
          "Cache-Control": "no-cache"
        });
        res.end(JSON.stringify({
          jsonrpc: "2.0",
          id,
          result
        }));
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ 
          jsonrpc: "2.0",
          id: requestData.id || null,
          error: { code: -32603, message: err.message }
        }));
      }
      return;
    }

    // Multipart upload endpoints
    if (ENABLE_HTTP && req.method === "POST" && req.url?.startsWith("/upload-and-convert")) {
      handleMultipartUpload(req, res, true);
      return;
    }
    if (ENABLE_HTTP && req.method === "POST" && req.url?.startsWith("/upload")) {
      handleMultipartUpload(req, res, false);
      return;
    }

    // Delegate to Hono for other routes
    const url = `http://${req.headers.host}${req.url}`;
    const bodyBuf =
      req.method === "GET" || req.method === "HEAD"
        ? undefined
        : await new Promise<Buffer>(resolve => {
            const chunks: Buffer[] = [];
            req.on("data", c => chunks.push(c));
            req.on("end", () => resolve(Buffer.concat(chunks)));
          });

    const fetchReq = new Request(url, {
      method: req.method,
      headers: req.headers as any,
      body: bodyBuf as any,
    });

    const resp = await app.fetch(fetchReq);
    res.writeHead(resp.status, Object.fromEntries(resp.headers.entries()));
    if (resp.body) {
      const buf = Buffer.from(await resp.arrayBuffer());
      res.end(buf);
    } else {
      res.end();
    }
  } catch (e: any) {
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: e.message || "Internal Server Error" }));
  }
});

if (ENABLE_HTTP || ENABLE_SSE || ENABLE_STREAMABLE_HTTP) {
  server.listen(PORT, async () => {
    await ensureDir(UPLOAD_ROOT);
    if (UV_PATH) {
      try { await access(UV_PATH); } catch {
        log(`[WARN] UV_PATH set but not accessible at ${UV_PATH}`);
      }
    }
    log(
      `Listening on 127.0.0.1:${PORT} (HTTP=${ENABLE_HTTP ? "on" : "off"}, SSE=${ENABLE_SSE ? "on" : "off"}, StreamableHTTP=${ENABLE_STREAMABLE_HTTP ? "on" : "off"})`,
    );
    log(`SSE endpoint: http://127.0.0.1:${PORT}${MCP_SSE_PATH}`);
    log(`Messages endpoint: http://127.0.0.1:${PORT}${MCP_MESSAGES_PATH}`);
    log(`Streamable HTTP endpoint: http://127.0.0.1:${PORT}${MCP_STREAMABLE_HTTP_PATH}`);
    log(`Upload dir: ${UPLOAD_ROOT}`);
  });
}

/* -------------------- Graceful shutdown -------------------- */
process.on('SIGTERM', async () => {
  log('Received SIGTERM, shutting down gracefully...');
  server.close(() => {
    log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', async () => {
  log('Received SIGINT, shutting down gracefully...');
  server.close(() => {
    log('Server closed');
    process.exit(0);
  });
});

/* -------------------- Optional stdio run -------------------- */

if (process.env.RUN_STDIO === "1") {
  import("@modelcontextprotocol/sdk/server/stdio.js").then(async ({ StdioServerTransport }) => {
    const stdioServer = createServer();
    const transport = new StdioServerTransport();
    await stdioServer.connect(transport);
    console.error("[STDIO] MCP stdio server started (RUN_STDIO=1)");
  }).catch((error) => {
    console.error("[STDIO] Failed to start MCP stdio server:", error);
    process.exit(1);
  });
}
