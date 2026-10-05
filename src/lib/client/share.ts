// Shared links carry the whole result in the URL fragment (#r=...), deflated
// and base64url-encoded. The fragment never reaches the server, so sharing
// stores nothing anywhere.
import type { AnalysisResult } from '@/types';

function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(text: string): Uint8Array {
  const binary = atob(text.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

async function pipe(bytes: Uint8Array, stream: CompressionStream | DecompressionStream): Promise<Uint8Array> {
  const out = new Response(new Blob([bytes as BlobPart]).stream().pipeThrough(stream));
  return new Uint8Array(await out.arrayBuffer());
}

export async function encodeResult(result: AnalysisResult): Promise<string> {
  const json = new TextEncoder().encode(JSON.stringify(result));
  if (typeof CompressionStream === 'undefined') return `j.${toBase64Url(json)}`;
  return `z.${toBase64Url(await pipe(json, new CompressionStream('deflate-raw')))}`;
}

export async function decodeResult(encoded: string): Promise<AnalysisResult | null> {
  try {
    const [format, data] = [encoded.slice(0, 1), encoded.slice(2)];
    const bytes = fromBase64Url(data);
    const json = format === 'z' ? await pipe(bytes, new DecompressionStream('deflate-raw')) : bytes;
    const result = JSON.parse(new TextDecoder().decode(json)) as AnalysisResult;
    return result && typeof result.query === 'string' && Array.isArray(result.indicators) ? result : null;
  } catch {
    return null;
  }
}

export async function shareUrl(result: AnalysisResult): Promise<string> {
  const base = `${window.location.origin}/results?q=${encodeURIComponent(result.query)}`;
  return `${base}#r=${await encodeResult(result)}`;
}
