import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';

// One reviewed reactor, named by its complete SHA256. The loader checks those
// bytes before handing them to a worker; ABI validation remains independent.
export function wasmAsset(root, base) {
  const id = 'virtual:quietproof-wasm';
  const artifact = () => {
    const bytes = readFileSync(resolve(root, process.env.QUIETPROOF_WASM));
    const sha = createHash('sha256').update(bytes).digest('hex');
    return { bytes, filename: `assets/quietproof.${sha}.wasm` };
  };
  return {
    name: 'quietproof-wasm-asset',
    resolveId(value) { if (value === id) return '\0' + id; },
    load(value) {
      if (value !== '\0' + id) return;
      if (!process.env.QUIETPROOF_WASM) {
        if (process.env.NODE_ENV === 'production') throw new Error('Set QUIETPROOF_WASM to the reviewed reactor before building.');
        return `export default ${JSON.stringify(base + 'wasm/quietproof.wasm')}`;
      }
      const { bytes, filename } = artifact();
      if (!this.meta.watchMode) this.emitFile({ type: 'asset', fileName: filename, source: bytes });
      return `export default ${JSON.stringify(base + filename)}`;
    },
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        if (!process.env.QUIETPROOF_WASM) return next();
        const { bytes, filename } = artifact();
        if (request.url !== base + filename) return next();
        response.setHeader('Content-Type', 'application/wasm');
        response.setHeader('Content-Length', bytes.length);
        response.end(bytes);
      });
    },
  };
}
