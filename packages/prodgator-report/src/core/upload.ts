import * as http from 'http';
import * as https from 'https';
import type { FileHandle } from 'fs/promises';
import type { ArtifactFile } from './artifacts';
import { openWorkspaceFile } from './safe-path';
import type { UploadSlot } from './types';

type UploadError = Error & { retryable?: boolean };

const refused = (message: string): UploadError => Object.assign(new Error(message), { retryable: false });

/**
 * The file was checked and hashed when the report was built, and is streamed only after Prodgator answers.
 * It is checked again here and streamed from that checked handle, so a file swapped for a symlink (or a
 * directory swapped for one) in between is refused instead of read.
 */
async function openForUpload(file: ArtifactFile): Promise<FileHandle> {
  const opened = await openWorkspaceFile(file.workspace, file.source ?? file.path, { display: file.path });
  if (!opened.ok) throw refused(`${opened.message} and was not uploaded`);
  if (opened.size !== file.size) {
    await opened.handle.close();
    throw refused(`${file.path} changed since it was hashed and was not uploaded`);
  }
  return opened.handle;
}

async function putOnce(slot: UploadSlot, file: ArtifactFile): Promise<void> {
  const handle = await openForUpload(file);
  // Closes the handle when it ends or is destroyed, which the finally below does on every outcome.
  const body = handle.createReadStream({ start: 0 });
  return new Promise<void>((resolve, reject) => {
    const url = new URL(slot.url);
    const mod = url.protocol === 'http:' ? http : https;
    // Node's http client sends Content-Length as given and never switches to chunked encoding when it is set;
    // S3 presigned PUTs need the exact signed length.
    // Presigned: the URL carries the signature. Never forward a credential header, whatever the slot lists.
    const headers = Object.fromEntries(Object.entries(slot.headers).filter(([k]) => !/^(proxy-)?authorization$|^cookie$/i.test(k)));
    const req = mod.request(url, { method: 'PUT', headers, timeout: 10 * 60_000 }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c: string) => { if (body.length < 4000) body += c; });
      res.on('end', () => {
        if (res.statusCode && res.statusCode < 300) return resolve();
        const code = /<Code>([^<]+)<\/Code>/.exec(body)?.[1] ?? `HTTP ${res.statusCode}`;
        const err: UploadError = new Error(`${file.path}: upload refused (${code})`);
        err.retryable = (res.statusCode ?? 0) >= 500;
        reject(err);
      });
    });
    req.on('timeout', () => { const err: UploadError = new Error(`${file.path}: upload timed out`); err.retryable = true; req.destroy(err); });
    req.on('error', (e: UploadError) => { if (e.retryable === undefined) e.retryable = true; reject(e); });
    body.on('error', reject).pipe(req);
  }).finally(() => body.destroy());
}

export async function uploadFile(slot: UploadSlot, file: ArtifactFile, attempts = 2): Promise<void> {
  for (let i = 1; ; i++) {
    try { return await putOnce(slot, file); } catch (e) { if (i >= attempts || !(e as UploadError).retryable) throw e; }
  }
}
