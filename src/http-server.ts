/* eslint-disable no-console */
import { Hono } from 'hono';
import http from 'node:http';
import Busboy from 'busboy';
import { randomBytes, createHash } from 'node:crypto';
import { mkdir, stat, readdir, unlink, realpath } from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import { basename, extname, join } from 'node:path';

// IMPORTANT: Add .js extensions for local files (NodeNext/Node16 ESM rules)
import { Markdownify } from './Markdownify.js';
import {
  YouTubeToMarkdownTool,
  BingSearchResultToMarkdownTool,
  WebpageToMarkdownTool,
  PDFToMarkdownTool,
  ImageToMarkdownTool,
  AudioToMarkdownTool,
  DocxToMarkdownTool,
  XlsxToMarkdownTool,
  PptxToMarkdownTool,
  GetMarkdownFileTool
} from './tools.js';

/**
 * ----------------------------
 * Configuration / Constants
 * ----------------------------
 */

const UPLOAD_ROOT = process.env.MD_SHARE_DIR || join(process.cwd(), 'uploads');
const MAX_UPLOAD_BYTES =
  Number(process.env.MAX_UPLOAD_BYTES || 50 * 1024 * 1024); // 50MB default
const ALLOWED_EXTENSIONS = (process.env.ALLOWED_EXTENSIONS || '')
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);
const UPLOAD_TTL_MS = Number(process.env.UPLOAD_TTL_MS || 60 * 60 * 1000);
const CLEAN_INTERVAL_MS = Number(process.env.CLEAN_INTERVAL_MS || 30 * 60 * 1000);
const PORT = Number(process.env.PORT) || 3000;
const ENFORCE_SHARE_DIR = !!process.env.MD_SHARE_DIR;

/**
 * ----------------------------
 * Helper Functions
 * ----------------------------
 */

async function ensureDir(dir: string) {
  try {
    await stat(dir);
  } catch {
    await mkdir(dir, { recursive: true });
  }
}

function randomFileName(ext: string) {
  return randomBytes(16).toString('hex') + ext.toLowerCase();
}

function isAllowedExtension(ext: string) {
  if (!ALLOWED_EXTENSIONS.length) return true;
  return ALLOWED_EXTENSIONS.includes(ext.toLowerCase());
}

async function saveStreamToFile(opts: {
  stream: NodeJS.ReadableStream;
  originalName: string;
  uploadDir: string;
  maxBytes: number;
}) {
  await ensureDir(opts.uploadDir);
  const ext = extname(opts.originalName) || '';
  if (!isAllowedExtension(ext)) {
    throw new Error(
      `Extension "${ext || '(none)'}" not allowed. Allowed: ${
        ALLOWED_EXTENSIONS.length ? ALLOWED_EXTENSIONS.join(',') : 'any'
      }`
    );
  }

  const finalName = randomFileName(ext);
  const absolutePath = join(opts.uploadDir, finalName);

  let size = 0;
  const sha = createHash('sha256');

  await new Promise<void>((resolve, reject) => {
    const ws = createWriteStream(absolutePath, { flags: 'wx' });
    opts.stream.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > opts.maxBytes) {
        ws.destroy();
        reject(new Error('File too large'));
        return;
      }
      sha.update(chunk);
      ws.write(chunk);
    });
    opts.stream.on('end', () => {
      ws.end();
    });
    ws.on('close', () => resolve());
    ws.on('error', (err) => reject(err));
    opts.stream.on('error', (err) => reject(err));
  });

  return {
    absolutePath,
    originalName: basename(opts.originalName),
    size,
    sha256: sha.digest('hex'),
    ext
  };
}

function sanitizeToolName(tool: string) {
  return tool.toLowerCase();
}

function toError(e: unknown): Error {
  return e instanceof Error ? e : new Error(typeof e === 'string' ? e : JSON.stringify(e));
}

// Tool names
const TOOL_NAMES = [
  YouTubeToMarkdownTool.name,
  BingSearchResultToMarkdownTool.name,
  WebpageToMarkdownTool.name,
  PDFToMarkdownTool.name,
  ImageToMarkdownTool.name,
  AudioToMarkdownTool.name,
  DocxToMarkdownTool.name,
  XlsxToMarkdownTool.name,
  PptxToMarkdownTool.name,
  GetMarkdownFileTool.name
];

// Classification
const URL_TOOL_SET = new Set([
  YouTubeToMarkdownTool.name,
  BingSearchResultToMarkdownTool.name,
  WebpageToMarkdownTool.name
]);

const FILE_TOOL_SET = new Set([
  PDFToMarkdownTool.name,
  ImageToMarkdownTool.name,
  AudioToMarkdownTool.name,
  DocxToMarkdownTool.name,
  XlsxToMarkdownTool.name,
  PptxToMarkdownTool.name
]);

const GET_TOOL = GetMarkdownFileTool.name;

/* ======================================================================
 * MCP HTTP EXTENSION (JSON-RPC over /mcp)
 * ====================================================================== */

const PROTOCOL_VERSION = '2024-11-0';
const MCP_HTTP_KEY = process.env.MCP_HTTP_KEY || null;

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: any;
}
interface JsonRpcSuccess {
  jsonrpc: '2.0';
  id: string | number | null;
  result: any;
}
interface JsonRpcError {
  jsonrpc: '2.0';
  id: string | number | null;
  error: { code: number; message: string };
}
type JsonRpcResponse = JsonRpcSuccess | JsonRpcError;

function rpcSuccess(id: any, result: any): JsonRpcSuccess {
  return { jsonrpc: '2.0', id, result };
}
function rpcError(id: any, code: number, message: string): JsonRpcError {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

// Lightweight per-tool schema/description
const MCP_TOOL_SCHEMAS: Record<
  string,
  { description: string; inputSchema: any }
> = {
  [YouTubeToMarkdownTool.name]: {
    description: 'Convert a YouTube URL to markdown.',
    inputSchema: {
      type: 'object',
      required: ['url'],
      properties: { url: { type: 'string' } },
      additionalProperties: false
    }
  },
  [BingSearchResultToMarkdownTool.name]: {
    description: 'Search Bing and summarize results as markdown.',
    inputSchema: {
      type: 'object',
      required: ['query'],
      properties: { query: { type: 'string' } },
      additionalProperties: false
    }
  },
  [WebpageToMarkdownTool.name]: {
    description: 'Fetch webpage and convert to markdown.',
    inputSchema: {
      type: 'object',
      required: ['url'],
      properties: { url: { type: 'string' } },
      additionalProperties: false
    }
  },
  [PDFToMarkdownTool.name]: {
    description: 'Convert PDF file to markdown.',
    inputSchema: {
      type: 'object',
      required: ['filepath'],
      properties: { filepath: { type: 'string' } },
      additionalProperties: false
    }
  },
  [ImageToMarkdownTool.name]: {
    description: 'Describe or OCR image to markdown.',
    inputSchema: {
      type: 'object',
      required: ['filepath'],
      properties: { filepath: { type: 'string' } },
      additionalProperties: false
    }
  },
  [AudioToMarkdownTool.name]: {
    description: 'Transcribe audio file to markdown.',
    inputSchema: {
      type: 'object',
      required: ['filepath'],
      properties: { filepath: { type: 'string' } },
      additionalProperties: false
    }
  },
  [DocxToMarkdownTool.name]: {
    description: 'Convert DOCX file to markdown.',
    inputSchema: {
      type: 'object',
      required: ['filepath'],
      properties: { filepath: { type: 'string' } },
      additionalProperties: false
    }
  },
  [XlsxToMarkdownTool.name]: {
    description: 'Convert XLSX file to markdown tables.',
    inputSchema: {
      type: 'object',
      required: ['filepath'],
      properties: { filepath: { type: 'string' } },
      additionalProperties: false
    }
  },
  [PptxToMarkdownTool.name]: {
    description: 'Convert PPTX slides to markdown.',
    inputSchema: {
      type: 'object',
      required: ['filepath'],
      properties: { filepath: { type: 'string' } },
      additionalProperties: false
    }
  },
  [GetMarkdownFileTool.name]: {
    description: 'Read an existing markdown file.',
    inputSchema: {
      type: 'object',
      required: ['filepath'],
      properties: { filepath: { type: 'string' } },
      additionalProperties: false
    }
  }
};

async function runMcpConversion(tool: string, args: any) {
  if (!TOOL_NAMES.includes(tool)) throw new Error(`Unknown tool: ${tool}`);

  if (URL_TOOL_SET.has(tool)) {
    const url = args?.url || (args?.query && `bing:${args.query}`);
    if (!url) throw new Error('url/query required');
    const result = await Markdownify.toMarkdown({
      url,
      uvPath: process.env.UV_PATH
    });
    return { markdown: result.text };
  }

  if (FILE_TOOL_SET.has(tool)) {
    const filepath = args?.filepath;
    if (!filepath) throw new Error('filepath required');
    if (ENFORCE_SHARE_DIR) {
      const realFile = await realpath(filepath);
      const base = await realpath(UPLOAD_ROOT);
      if (!realFile.startsWith(base))
        throw new Error('File path is outside allowed directory');
    }
    const result = await Markdownify.toMarkdown({
      filePath: filepath,
      uvPath: process.env.UV_PATH
    });
    return { markdown: result.text };
  }

  if (tool === GET_TOOL) {
    const filepath = args?.filepath;
    if (!filepath) throw new Error('filepath required');
    if (ENFORCE_SHARE_DIR) {
      const realFile = await realpath(filepath);
      const base = await realpath(UPLOAD_ROOT);
      if (!realFile.startsWith(base))
        throw new Error('File path is outside allowed directory');
    }
    const lower = filepath.toLowerCase();
    if (!lower.endsWith('.md') && !lower.endsWith('.markdown')) {
      throw new Error('File is not a markdown file');
    }
    const result = await Markdownify.get({ filePath: filepath });
    return { markdown: result.text };
  }

  throw new Error(`Unhandled tool: ${tool}`);
}

async function handleMcpRequest(r: JsonRpcRequest): Promise<JsonRpcResponse> {
  const { id = null, method, params = {} } = r;
  try {
    switch (method) {
      case 'initialize':
        return rpcSuccess(id, {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: {}, resources: {} },
          serverInfo: { name: 'markdownify-http', version: '1.0.0' }
        });

      case 'tools/list':
      case 'list_tools':
        return rpcSuccess(id, {
          tools: TOOL_NAMES.map((name) => ({
            name,
            description:
              MCP_TOOL_SCHEMAS[name]?.description || `Tool ${name}`,
            inputSchema:
              MCP_TOOL_SCHEMAS[name]?.inputSchema || { type: 'object' }
          }))
        });

      case 'tools/call':
      case 'call_tool': {
        const { name, arguments: args } = params;
        if (!name) throw new Error('name is required');
        const { markdown } = await runMcpConversion(name, args || {});
        return rpcSuccess(id, {
          content: [{ type: 'text', text: markdown }],
          meta: { tool: name }
        });
      }

      case 'ping':
        return rpcSuccess(id, { pong: true, ts: Date.now() });

      case 'shutdown':
        setTimeout(() => process.exit(0), 5);
        return rpcSuccess(id, { ok: true });

      default:
        return rpcError(id, -32601, 'Method not found');
    }
  } catch (e) {
    const err = toError(e);
    return rpcError(id, -32000, err.message);
  }
}

/**
 * ----------------------------
 * Hono App
 * ----------------------------
 */

const app = new Hono();

app.get('/', (c) =>
  c.json({
    status: 'ok',
    tools: TOOL_NAMES,
    uploadDir: UPLOAD_ROOT,
    maxUploadBytes: MAX_UPLOAD_BYTES
  })
);

app.post('/convert', async (c) => {
  try {
    const body = await c.req.json<{
      tool: string;
      filepath?: string;
      url?: string;
      uvPath?: string;
    }>();
    const { tool, filepath, url, uvPath } = body;

    if (!tool) return c.json({ error: 'tool is required' }, 400);
    if (!TOOL_NAMES.includes(tool)) {
      return c.json({ error: 'unknown tool', provided: tool }, 400);
    }

    async function checkPathInsideShare(p?: string) {
      if (!p || !ENFORCE_SHARE_DIR) return;
      const realFile = await realpath(p);
      const realBase = await realpath(UPLOAD_ROOT);
      if (!realFile.startsWith(realBase)) {
        throw new Error('File path is outside allowed directory');
      }
    }

    if (URL_TOOL_SET.has(tool)) {
      if (!url) return c.json({ error: 'url is required for this tool' }, 400);
      const result = await Markdownify.toMarkdown({
        url,
        uvPath: uvPath || process.env.UV_PATH
      });
      return c.json({ ok: true, tool, markdown: result.text });
    }

    if (FILE_TOOL_SET.has(tool)) {
      if (!filepath) return c.json({ error: 'filepath is required for this tool' }, 400);
      await checkPathInsideShare(filepath);
      const result = await Markdownify.toMarkdown({
        filePath: filepath,
        uvPath: uvPath || process.env.UV_PATH
      });
      return c.json({ ok: true, tool, markdown: result.text });
    }

    if (tool === GET_TOOL) {
      if (!filepath) return c.json({ error: 'filepath is required for this tool' }, 400);
      await checkPathInsideShare(filepath);
      const result = await Markdownify.get({ filePath: filepath });
      return c.json({ ok: true, tool, markdown: result.text });
    }

    return c.json({ error: 'unhandled tool' }, 400);
  } catch (e) {
    const err = toError(e);
    return c.json({ error: err.message || 'conversion error' }, 500);
  }
});

/* ---------------- MCP over HTTP endpoint (/mcp) ---------------- */
app.post('/mcp', async (c) => {
  if (MCP_HTTP_KEY && c.req.header('x-api-key') !== MCP_HTTP_KEY) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  const urlObj = new URL(c.req.url, 'http://localhost');
  const wantStream = urlObj.searchParams.get('stream') === '1';

  let payload: any;
  try {
    payload = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON' }, 400);
  }

  const requests: JsonRpcRequest[] = Array.isArray(payload) ? payload : [payload];

  if (!wantStream) {
    const responses: JsonRpcResponse[] = [];
    for (const r of requests) {
      responses.push(await handleMcpRequest(r));
    }
    return c.json(Array.isArray(payload) ? responses : responses[0]);
  }

  // SSE streaming
  const stream = new ReadableStream({
    async start(controller) {
      const enc = new TextEncoder();
      function sendEvent(obj: any, event = 'message') {
        controller.enqueue(enc.encode(`event: ${event}\ndata: ${JSON.stringify(obj)}\n\n`));
      }
      for (const r of requests) {
        const resp = await handleMcpRequest(r);
        sendEvent(resp);
      }
      sendEvent({}, 'end');
      controller.close();
    }
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no'
    }
  });
});

/**
 * ----------------------------
 * Multipart Upload Handling
 * ----------------------------
 */

function handleMultipartUpload(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  { autoConvert }: { autoConvert: boolean }
) {
  const contentType = req.headers['content-type'] || '';
  if (!contentType.startsWith('multipart/form-data')) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Content-Type must be multipart/form-data' }));
    return;
  }

  const tool = autoConvert
    ? sanitizeToolName(
        (new URL(req.url || '', `http://${req.headers.host}`).searchParams.get('tool') ||
          PDFToMarkdownTool.name)
      )
    : null;

  const busboy = Busboy({
    headers: { 'content-type': contentType },
    limits: { fileSize: MAX_UPLOAD_BYTES, files: 1 }
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

  busboy.on('file', (_field, fileStream, info) => {
    const p = saveStreamToFile({
      stream: fileStream,
      originalName: info.filename,
      uploadDir: UPLOAD_ROOT,
      maxBytes: MAX_UPLOAD_BYTES
    })
      .then((meta) => {
        if (!savedMeta) savedMeta = meta;
      })
      .catch((err) => {
        fileError = toError(err);
        fileStream.resume();
      });
    filePromises.push(p);
  });

  busboy.on('error', (err) => {
    fileError = toError(err);
  });

  busboy.on('finish', async () => {
    try {
      if (filePromises.length) {
        await Promise.all(filePromises);
      }
    } catch {
      // fileError already set if any
    }

    if (fileError) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: fileError.message }));
      return;
    }

    if (!savedMeta) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'No file received' }));
      return;
    }

    if (!autoConvert) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          ok: true,
          filepath: savedMeta.absolutePath,
          size: savedMeta.size,
          sha256: savedMeta.sha256,
          originalName: savedMeta.originalName
        })
      );
      return;
    }

    // Auto-convert
    try {
      let markdown: string | undefined;

      if (FILE_TOOL_SET.has(tool || '')) {
        const result = await Markdownify.toMarkdown({
          filePath: savedMeta.absolutePath,
          uvPath: process.env.UV_PATH
        });
        markdown = result.text;
      } else if (tool === GET_TOOL) {
        const result = await Markdownify.get({ filePath: savedMeta.absolutePath });
        markdown = result.text;
      } else {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Tool "${tool}" not valid for auto-convert upload` }));
        return;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          ok: true,
          tool,
          filepath: savedMeta.absolutePath,
          markdown,
          size: savedMeta.size,
          sha256: savedMeta.sha256,
          originalName: savedMeta.originalName
        })
      );
    } catch (err) {
      const e = toError(err);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message || 'auto-convert failed' }));
    }
  });

  req.pipe(busboy);
}

/**
 * ----------------------------
 * Periodic Cleanup
 * ----------------------------
 */

async function cleanupOldUploads() {
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
}

setInterval(cleanupOldUploads, CLEAN_INTERVAL_MS).unref();

/**
 * ----------------------------
 * HTTP Server
 * ----------------------------
 */

const server = http.createServer(async (req, res) => {
  try {
    if (!req.url) {
      res.writeHead(400);
      res.end('Bad Request');
      return;
    }

    if (req.method === 'POST' && req.url.startsWith('/upload-and-convert')) {
      handleMultipartUpload(req, res, { autoConvert: true });
      return;
    }
    if (req.method === 'POST' && req.url.startsWith('/upload')) {
      handleMultipartUpload(req, res, { autoConvert: false });
      return;
    }

    // Delegate remaining to Hono
    const url = `http://${req.headers.host}${req.url}`;
    const body =
      req.method === 'GET' || req.method === 'HEAD'
        ? undefined
        : await new Promise<Buffer>((resolve) => {
            const chunks: Buffer[] = [];
            req.on('data', (c) => chunks.push(c));
            req.on('end', () => resolve(Buffer.concat(chunks)));
          });

    const fetchReq = new Request(url, {
      method: req.method,
      headers: req.headers as any,
      body: body as any
    });

    const response = await app.fetch(fetchReq);
    res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
    if (response.body) {
      const buf = Buffer.from(await response.arrayBuffer());
      res.end(buf);
    } else {
      res.end();
    }
  } catch (e) {
    const err = toError(e);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: err.message || 'Internal Server Error' }));
  }
});

server.listen(PORT, () => {
  console.log(`HTTP server listening on http://localhost:${PORT}`);
  console.log(`Upload directory: ${UPLOAD_ROOT}`);
  console.log(`Tools: ${TOOL_NAMES.join(', ')}`);
  if (MCP_HTTP_KEY) {
    console.log('MCP endpoint secured with API key.');
  }
  console.log('MCP endpoint: POST /mcp (add ?stream=1 for SSE)');
});
