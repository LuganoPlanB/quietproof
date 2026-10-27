import { createHash } from 'node:crypto';

// VitePress emits small theme/bootstrap scripts. Authorize their exact build
// bytes instead of allowing arbitrary inline scripts or JavaScript evaluation.
export function secureHtml(html) {
  const hashes = [];
  for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
    if (!/\bsrc\s*=/i.test(match[1]) && match[2])
      hashes.push(`'sha256-${createHash('sha256').update(match[2]).digest('base64')}'`);
  }
  const policy = ["default-src 'self'", `script-src 'self' 'wasm-unsafe-eval' ${[...new Set(hashes)].join(' ')}`,
    "worker-src 'self'", "connect-src 'self' https://blockstream.info/api/ https://blockstream.info/signet/api/",
    "style-src 'self' 'unsafe-inline'", "img-src 'self' data:", "font-src 'self'",
    "object-src 'none'", "base-uri 'self'", "form-action 'none'"].join('; ');
  return html.replace('<head>', `<head><meta http-equiv="Content-Security-Policy" content="${policy}"><meta name="referrer" content="no-referrer">`);
}
