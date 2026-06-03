import { describe, it, expect } from 'vitest';
import { toBase64Std, fromBase64Std, toBase64UrlUnpadded, utf8 } from '../src/encoding';

describe('base64 standard (BASE64_STANDARD — OPAQUE wire blobs)', () => {
  it('encodes the +// alphabet bytes to standard base64', () => {
    // 0xfb,0xff,0xbf chosen to force the standard-alphabet chars '+' and '/'.
    expect(toBase64Std(new Uint8Array([0xfb, 0xff, 0xbf]))).toBe('+/+/');
  });

  it('pads standard base64 with =', () => {
    expect(toBase64Std(new Uint8Array([0x01]))).toBe('AQ==');
    expect(toBase64Std(new Uint8Array([0x01, 0x02]))).toBe('AQI=');
  });

  it('round-trips arbitrary bytes (encode → decode)', () => {
    const bytes = new Uint8Array([0x00, 0x10, 0x7f, 0x80, 0xfb, 0xff, 0xbf, 0xa9]);
    expect(fromBase64Std(toBase64Std(bytes))).toEqual(bytes);
  });

  it('decodes a known standard-base64 string', () => {
    expect(fromBase64Std('+/+/')).toEqual(new Uint8Array([0xfb, 0xff, 0xbf]));
  });

  it('round-trips an empty Uint8Array', () => {
    const empty = new Uint8Array(0);
    expect(fromBase64Std(toBase64Std(empty))).toEqual(empty);
    expect(toBase64UrlUnpadded(empty)).toBe('');
  });
});

describe('base64url unpadded (RawURLEncoding — blind index)', () => {
  it('uses the url-safe alphabet (- and _ instead of + and /)', () => {
    expect(toBase64UrlUnpadded(new Uint8Array([0xfb, 0xff, 0xbf]))).toBe('-_-_');
  });

  it('strips = padding and never emits + or /', () => {
    expect(toBase64UrlUnpadded(new Uint8Array([0x01]))).toBe('AQ');
    const url = toBase64UrlUnpadded(new Uint8Array([0xfb, 0xff, 0xbf, 0x01]));
    expect(url).not.toContain('=');
    expect(url).not.toContain('+');
    expect(url).not.toContain('/');
  });
});

describe('utf8', () => {
  it('encodes ASCII and multibyte correctly', () => {
    expect(utf8('A')).toEqual(new Uint8Array([0x41]));
    expect(utf8('é')).toEqual(new Uint8Array([0xc3, 0xa9])); // U+00E9 → 2-byte UTF-8
  });
});
