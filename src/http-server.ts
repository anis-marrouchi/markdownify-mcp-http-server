import { z } from "zod";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { Markdownify } from "./Markdownify.js";
import * as tools from "./tools.js";
import { CallToolRequest } from "@modelcontextprotocol/sdk/types.js";
import is_ip_private from "private-ip";
import { URL } from "node:url";

/* ---------------- Original (UNCHANGED) MCP stdio server ---------------- */

const RequestPayloadSchema = z.object({
  filepath: z.string().optional(),
  url: z.string().optional(),
  projectRoot: z.string().optional(),
  uvPath: z.string().optional(),
});

export function createServer() {
  const server = new Server(
    {
      name: "mcp-markdownify-server",
      version: "0.1.0",
    },
    {
      capabilities: {
        tools: {},
      },
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: Object.values(tools),
    };
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
          case tools.WebpageToMarkdownTool.name:
            if (!validatedArgs.url) {
              throw new Error("URL is required for this tool");
            }

            const parsedUrl = new URL(validatedArgs.url);
            if (!["http:", "https:"].includes(parsedUrl.protocol)) {
              throw new Error("Only http: and https: schemes are allowed.");
            }
            if (is_ip_private(parsedUrl.hostname)) {
              throw new Error(
                `Fetching ${validatedArgs.url} is potentially dangerous, aborting.`,
              );
            }

            result = await Markdownify.toMarkdown({
              url: validatedArgs.url,
              projectRoot: validatedArgs.projectRoot,
              uvPath: validatedArgs.uvPath || process.env.UV_PATH,
            });
            break;

          case tools.PDFToMarkdownTool.name:
          case tools.ImageToMarkdownTool.name:
          case tools.AudioToMarkdownTool.name:
          case tools.DocxToMarkdownTool.name:
          case tools.XlsxToMarkdownTool.name:
          case tools.PptxToMarkdownTool.name:
            if (!validatedArgs.filepath) {
              throw new Error("File path is required for this tool");
            }
            result = await Markdownify.toMarkdown({
              filePath: validatedArgs.filepath,
              projectRoot: validatedArgs.projectRoot,
              uvPath: validatedArgs.uvPath || process.env.UV_PATH,
            });
            break;

          case tools.GetMarkdownFileTool.name:
            if (!validatedArgs.filepath) {
              throw new Error("File path is required for this tool");
            }
            result = await Markdownify.get({
              filePath: validatedArgs.filepath,
            });
            break;

          default:
            throw new Error("Tool not found");
        }

        return {
          content: [
            { type: "text", text: `Output file: ${result.path}` },
            { type: "text", text: `Converted content:` },
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
        } else {
          console.error(e);
          return {
            content: [{ type: "text", text: `Error: Unknown error occurred` }],
            isError: true,
          };
        }
      }
    },
  );

  return server;
}

/* --------------- EXTRA CAPABILITY: HTTP REST + Upload + SSE --------------- */
/**
 * This block adds:
 *   - REST endpoints (if ENABLE_HTTP)
 *   - File uploads (/upload, /upload-and-convert)
 *   - JSON POST /convert
 *   - GET / (tool list)
 *   - GET /healthz
 *   - Legacy MCP HTTP+SSE transport (if ENABLE_SSE) with:
 *        GET /mcp (SSE)
 *        POST /messages (JSON-RPC request forwarding)
 *
 * All logs in this section go to stderr to avoid polluting MCP stdio.
 */

import { randomBytes, createHash, randomUUID } from "node:crypto";
import {
  createWriteStream,
  existsSync,
} from "node:fs";
import {
  mkdir,
  stat,
  readdir,
  unlink,
  realpath,
  readFile,
} from "node:fs/promises";
import { basename, extname, join } from "node:path";
import http, { IncomingMessage, ServerResponse } from "node:http";
import Busboy from "busboy";

/* ---- Environment / Config ---- */
const ENABLE_HTTP = !!process.env.ENABLE_HTTP;
const ENABLE_SSE = !!process.env.ENABLE_SSE;
const PORT = Number(process.env.PORT || 3100);
const UPLOAD_ROOT = process.env.MD_SHARE_DIR || join(process.cwd(), "uploads");
const ENFORCE_SHARE_DIR = !!process.env.MD_SHARE_DIR;
const MAX_UPLOAD_BYTES = Number(process.env.MAX_UPLOAD_BYTES || 50 * 1024 * 1024);
const UPLOAD_TTL_MS = Number(process.env.UPLOAD_TTL_MS || 60 * 60 * 1000);
const CLEAN_INTERVAL_MS = Number(process.env.CLEAN_INTERVAL_MS || 30 * 60 * 1000);
const ALLOWED_EXTENSIONS = (process.env.ALLOWED_EXTENSIONS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);
const UV_PATH = process.env.UV_PATH;
const MCP_SSE_PATH = process.env.MCP_SSE_PATH || "/mcp";
const MCP_MESSAGES_PATH = process.env.MCP_MESSAGES_PATH || "/messages";
const MCP_HTTP_TOKEN = process.env.MCP_HTTP_TOKEN || ""; // optional security
const PROTOCOL_VERSION = "2024-11-0";

/* ---- Shared Logger (stderr) ---- */
function httpLog(...args: any[]) {
  console.error("[HTTP]", ...args);
}

/* ---- Helpers ---- */
async function ensureDir(dir: string) {
  try {
    await stat(dir);
  } catch {
    await mkdir(dir, { recursive: true });
  }
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
  const rp = await realpath(p);
  const base = await realpath(UPLOAD_ROOT);
  if (!rp.startsWith(base)) throw new Error("File path outside allowed directory");
  return rp;
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

/* ---- Tool Classification (re‑use names) ---- */
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
const TOOL_NAMES = Object.values(tools).map((t) => t.name);

/* ---- Conversion Logic (shared) ---- */
async function runConversion(
  toolName: string,
  { filepath, url }: { filepath?: string; url?: string },
) {
  if (!TOOL_NAMES.includes(toolName)) throw new Error(`unknown tool "${toolName}"`);

  if (URL_TOOL_SET.has(toolName)) {
    if (!url) throw new Error("url is required");
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      throw new Error("Only http/https URLs allowed");
    }
    if (is_ip_private(parsed.hostname)) {
      throw new Error(`Fetching ${url} is potentially dangerous`);
    }
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
    if (!lower.endsWith(".md") && !lower.endsWith(".markdown")) {
      throw new Error("File is not markdown");
    }
    const r = await Markdownify.get({ filePath: fp });
    return r.text;
  }

  throw new Error(`Unhandled tool "${toolName}"`);
}

/* ---------------- REST HTTP Server (optional) ---------------- */
let httpServer: http.Server | undefined;

if (ENABLE_HTTP || ENABLE_SSE) {
  httpServer = http.createServer(async (req, res) => {
    try {
      if (!req.url) {
        res.writeHead(400).end("Bad Request");
        return;
      }

      /* ---- Legacy MCP SSE GET endpoint ---- */
      if (ENABLE_SSE && req.method === "GET" && req.url.startsWith(MCP_SSE_PATH)) {
        if (MCP_HTTP_TOKEN && req.headers["x-mcp-token"] !== MCP_HTTP_TOKEN) {
          res.writeHead(401).end("unauthorized");
          return;
        }
        startSseSession(req, res);
        return;
      }

      /* ---- Legacy MCP POST messages endpoint ---- */
      if (ENABLE_SSE && req.method === "POST" && req.url === MCP_MESSAGES_PATH) {
        if (MCP_HTTP_TOKEN && req.headers["x-mcp-token"] !== MCP_HTTP_TOKEN) {
          res.writeHead(401, { "Content-Type": "application/json" })
            .end(JSON.stringify({ error: "unauthorized" }));
          return;
        }
        await handleSseMessagePost(req, res);
        return;
      }

      /* ---- Upload endpoints ---- */
      if (ENABLE_HTTP && req.method === "POST" && req.url.startsWith("/upload-and-convert")) {
        handleMultipartUpload(req, res, true);
        return;
      }
      if (ENABLE_HTTP && req.method === "POST" && req.url.startsWith("/upload")) {
        handleMultipartUpload(req, res, false);
        return;
      }

      /* ---- Root listing ---- */
      if (ENABLE_HTTP && req.method === "GET" && req.url === "/") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            status: "ok",
            tools: TOOL_NAMES,
            uploadDir: UPLOAD_ROOT,
            maxUploadBytes: MAX_UPLOAD_BYTES,
            http: true,
            sse: !!ENABLE_SSE,
          }),
        );
        return;
      }

      /* ---- Health ---- */
      if (req.method === "GET" && req.url === "/healthz") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, ts: Date.now() }));
        return;
      }

      /* ---- JSON convert ---- */
      if (ENABLE_HTTP && req.method === "POST" && req.url === "/convert") {
        const body = await getBody(req);
        let json: any;
        try {
          json = JSON.parse(body.toString() || "{}");
        } catch {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Invalid JSON" }));
          return;
        }
        const { tool, filepath, url } = json;
        if (!tool) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "tool is required" }));
          return;
        }
        try {
          const markdown = await runConversion(tool, { filepath, url });
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: true, tool, markdown }));
        } catch (e) {
          const err = e instanceof Error ? e : new Error(String(e));
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: err.message }));
        }
        return;
      }

      /* ---- 404 ---- */
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not Found" }));
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: e.message || "Internal Server Error" }));
    }
  });

  httpServer.listen(PORT, async () => {
    await ensureDir(UPLOAD_ROOT);
    httpLog(
      `Listening on 127.0.0.1:${PORT} (HTTP=${ENABLE_HTTP ? "on" : "off"}, SSE=${ENABLE_SSE ? "on" : "off"})`,
    );
    httpLog(`Upload dir: ${UPLOAD_ROOT}`);
  });

  /* ---- Periodic Upload Cleanup ---- */
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
        } catch {
          /* ignore */
        }
      }
    } catch {
      /* ignore */
    }
  }, CLEAN_INTERVAL_MS).unref();
}

/* ---------------- Multipart Upload Handler ---------------- */
function handleMultipartUpload(
  req: IncomingMessage,
  res: ServerResponse,
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
      .then((meta) => {
        if (!savedMeta) savedMeta = meta;
      })
      .catch((err) => {
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
    } catch {
      /* fileError would be set */
    }
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
      res.end(
        JSON.stringify({
          ok: true,
          filepath: savedMeta.absolutePath,
          size: savedMeta.size,
          sha256: savedMeta.sha256,
          originalName: savedMeta.originalName,
        }),
      );
      return;
    }
    try {
      if (!toolName) throw new Error("tool not specified");
      const markdown = await runConversion(toolName, {
        filepath: savedMeta.absolutePath,
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          ok: true,
          tool: toolName,
          filepath: savedMeta.absolutePath,
          markdown,
          size: savedMeta.size,
          sha256: savedMeta.sha256,
          originalName: savedMeta.originalName,
        }),
      );
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: err.message }));
    }
  });

  req.pipe(busboy);
}

/* ---------------- HTTP Helper: getBody ---------------- */
async function getBody(req: IncomingMessage) {
  return await new Promise<Buffer>((resolve) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
  });
}

/* ---------------- Legacy HTTP+SSE MCP Transport ---------------- */

/**
 * For remote MCP clients that configure:
 * {
 *   "type": "sse",
 *   "url": "https://host",
 *   "sse_path": "/mcp",
 *   "messages_path": "/messages",
 *   "headers": { "x-mcp-token": "SHARED" }
 * }
 *
 * Client Flow:
 *  GET /mcp  -> opens SSE, receives {"type":"session","sessionId": "..."}
 *  POST /messages { sessionId, jsonrpc, id, method, params } (one per call)
 *  Response is streamed back to SSE as JSON-RPC object
 */

interface SseSession {
  id: string;
  res: ServerResponse;
  closed: boolean;
}

const sseSessions = new Map<string, SseSession>();

function writeSse(res: ServerResponse, obj: any) {
  res.write(`data: ${JSON.stringify(obj)}\n\n`);
}

function startSseSession(_req: IncomingMessage, res: ServerResponse) {
  const sessionId = randomUUID();
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.write("\n"); // flush
  sseSessions.set(sessionId, { id: sessionId, res, closed: false });
  writeSse(res, { type: "session", sessionId, protocolVersion: PROTOCOL_VERSION });

  res.on("close", () => {
    const s = sseSessions.get(sessionId);
    if (s) {
      s.closed = true;
      sseSessions.delete(sessionId);
    }
  });
}

/* ---- Minimal JSON-RPC dispatch implementing subset: initialize, list_tools, call_tool ---- */
async function handleSseMessagePost(req: IncomingMessage, res: ServerResponse) {
  const body = await getBody(req);
  let msg: any;
  try {
    msg = JSON.parse(body.toString());
  } catch {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "invalid json" }));
    return;
  }

  const sessionId = msg.sessionId;
  if (!sessionId || !sseSessions.has(sessionId)) {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "invalid or missing sessionId" }));
    return;
  }

  // Acknowledge quickly (client doesn't *need* the response body here)
  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ ok: true }));

  const session = sseSessions.get(sessionId);
  if (!session || session.closed) return;

  const { id = null, method, params = {} } = msg;

  function sendResult(result: any) {
    if (session && !session.closed) writeSse(session.res, { jsonrpc: "2.0", id, result });
  }
  function sendError(code: number, message: string) {
    if (session && !session.closed)
      writeSse(session.res, { jsonrpc: "2.0", id, error: { code, message } });
  }

  try {
    switch (method) {
      case "initialize":
        sendResult({
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: {
            name: "markdownify-mcp-http",
            version: "0.1.0",
          },
        });
        break;
      case "list_tools":
      case "tools/list":
        sendResult({
          tools: Object.values(tools),
        });
        break;
      case "call_tool":
      case "tools/call": {
        const { name, arguments: args } = params;
        if (!name) throw new Error("name is required");
        // reuse original validation
        const validatedArgs = RequestPayloadSchema.parse(args || {});
        let result;
        switch (name) {
          case tools.YouTubeToMarkdownTool.name:
          case tools.BingSearchResultToMarkdownTool.name:
          case tools.WebpageToMarkdownTool.name: {
            if (!validatedArgs.url) {
              throw new Error("URL is required for this tool");
            }
            const parsedUrl = new URL(validatedArgs.url);
            if (!["http:", "https:"].includes(parsedUrl.protocol)) {
              throw new Error("Only http: and https: schemes are allowed.");
            }
            if (is_ip_private(parsedUrl.hostname)) {
              throw new Error("Potentially dangerous URL (private IP)");
            }
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
            if (!validatedArgs.filepath) {
              throw new Error("File path is required for this tool");
            }
            // sandbox if MD_SHARE_DIR enforced
            await sandboxFilePath(validatedArgs.filepath);
            result = await Markdownify.toMarkdown({
              filePath: validatedArgs.filepath,
              projectRoot: validatedArgs.projectRoot,
              uvPath: validatedArgs.uvPath || process.env.UV_PATH,
            });
            break;
          }
          case tools.GetMarkdownFileTool.name: {
            if (!validatedArgs.filepath) {
              throw new Error("File path is required for this tool");
            }
            await sandboxFilePath(validatedArgs.filepath);
            result = await Markdownify.get({
              filePath: validatedArgs.filepath,
            });
            break;
          }
          default:
            throw new Error("Tool not found");
        }
        sendResult({
          content: [
            { type: "text", text: `Output file: ${result.path}` },
            { type: "text", text: "Converted content:" },
            { type: "text", text: result.text },
          ],
          isError: false,
        });
        break;
      }
      default:
        sendError(-32601, "Method not found");
    }
  } catch (e) {
    const err = e instanceof Error ? e : new Error(String(e));
    sendResult({
      content: [{ type: "text", text: `Error: ${err.message}` }],
      isError: true,
    });
  }
}

/* ---------------- End of SSE / HTTP Extension ---------------- */
