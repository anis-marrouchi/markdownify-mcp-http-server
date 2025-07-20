import { createWriteStream } from 'node:fs';
import { randomBytes, createHash } from 'node:crypto';
import { mkdir, stat } from 'node:fs/promises';
import { join, basename, extname } from 'node:path';

export interface SavedFileInfo {
  absolutePath: string;
  originalName: string;
  size: number;
  sha256: string;
  ext: string;
}

export async function ensureDir(dir: string) {
  try { await stat(dir); } catch { await mkdir(dir, { recursive: true }); }
}

export function safeBaseName(original: string) {
  // Remove any directory parts, keep only last segment
  const base = basename(original).replace(/[^A-Za-z0-9._-]/g, '_');
  return base.length ? base : 'file';
}

export function randomFileName(ext: string) {
  return randomBytes(16).toString('hex') + ext.toLowerCase();
}

export function hashBuffer(buf: Buffer) {
  return createHash('sha256').update(buf).digest('hex');
}

export async function saveStreamToFile(opts: {
  stream: NodeJS.ReadableStream;
  uploadDir: string;
  originalName: string;
  maxBytes: number;
}): Promise<SavedFileInfo> {
  await ensureDir(opts.uploadDir);
  const ext = extname(opts.originalName) || '';
  const finalName = randomFileName(ext);
  const absolutePath = join(opts.uploadDir, finalName);

  let size = 0;
  const chunks: Buffer[] = [];
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
      chunks.push(chunk);
      ws.write(chunk);
    });
    opts.stream.on('end', () => {
      ws.end();
    });
    ws.on('close', () => resolve());
    ws.on('error', reject);
    opts.stream.on('error', reject);
  });

  return {
    absolutePath,
    originalName: opts.originalName,
    size,
    sha256: sha.digest('hex'),
    ext
  };
}
