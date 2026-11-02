export const MAX_SUMMARY_BYTES = 1024 * 1024;
const MARKER = '\n\n…(truncated by prodgator-report)';

export function truncateUtf8(text: string, maxBytes: number): { text: string; truncated: boolean } {
  const bytes = Buffer.from(text, 'utf8');
  if (bytes.length <= maxBytes) return { text, truncated: false };
  let end = maxBytes - Buffer.byteLength(MARKER, 'utf8');
  while (end > 0 && (bytes[end] & 0xc0) === 0x80) end--;       // back off to the start of a UTF-8 character
  return { text: bytes.subarray(0, end).toString('utf8') + MARKER, truncated: true };
}
