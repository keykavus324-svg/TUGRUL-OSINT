import { describe, it, expect } from 'vitest';
import { gpsToDecimal, metadataToText, parseMetadata, sniffFormat } from './exif';

/* ── fixture builders ────────────────────────────────────────── */

const u16le = (n: number) => [n & 0xff, (n >> 8) & 0xff];
const u32le = (n: number) => [n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff];
const u16be = (n: number) => [(n >> 8) & 0xff, n & 0xff];
const u32be = (n: number) => [(n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];

/**
 * A minimal little-endian TIFF block with:
 *   IFD0  Make=TestCam, Model=ModelX, GPS pointer
 *   GPS   LatRef=N, Lat=41/1,0/1,0/1 · LonRef=E, Lon=29/1,0/1,0/1
 * Offsets are laid out by hand; see the comments for the arithmetic.
 */
function buildTiff(): number[] {
  const b: number[] = [];
  const push = (...n: number[]) => b.push(...n);

  push(0x49, 0x49, 0x2a, 0x00);          // 'II', 42, IFD0 @ 8
  push(...u32le(8));

  push(...u16le(3));                      // IFD0, 3 entries → ends at 50
  push(...u16le(0x010f), ...u16le(2), ...u32le(8), ...u32le(50));   // Make  → 50
  push(...u16le(0x0110), ...u16le(2), ...u32le(7), ...u32le(58));   // Model → 58
  push(...u16le(0x8825), ...u16le(4), ...u32le(1), ...u32le(66));   // GPS   → 66
  push(...u32le(0));                      // no next IFD

  push(84, 101, 115, 116, 67, 97, 109, 0);        // "TestCam\0"  50..57
  push(77, 111, 100, 101, 108, 88, 0);            // "ModelX\0"   58..64
  push(0);                                        // pad          65

  push(...u16le(4));                      // GPS IFD → ends at 120
  push(...u16le(0x0001), ...u16le(2), ...u32le(2), 78, 0, 0, 0);          // LatRef "N"
  push(...u16le(0x0002), ...u16le(5), ...u32le(3), ...u32le(120));        // Lat → 120
  push(...u16le(0x0003), ...u16le(2), ...u32le(2), 69, 0, 0, 0);          // LonRef "E"
  push(...u16le(0x0004), ...u16le(5), ...u32le(3), ...u32le(144));        // Lon → 144
  push(...u32le(0));

  for (const [n, d] of [[41, 1], [0, 1], [0, 1]]) push(...u32le(n), ...u32le(d)); // 120..143
  for (const [n, d] of [[29, 1], [0, 1], [0, 1]]) push(...u32le(n), ...u32le(d)); // 144..167

  return b;
}

function buildJpegWithExif(): Uint8Array {
  const tiff = buildTiff();
  const app1Length = 2 + 6 + tiff.length;
  return new Uint8Array([
    0xff, 0xd8,                              // SOI
    0xff, 0xe1, ...u16be(app1Length),        // APP1
    0x45, 0x78, 0x69, 0x66, 0x00, 0x00,      // "Exif\0\0"
    ...tiff,
    0xff, 0xda, 0xff, 0xd9,                  // SOS + EOI
  ]);
}

function buildPng(text?: { keyword: string; value: string }): Uint8Array {
  const b: number[] = [];
  b.push(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a);

  const chunk = (type: string, data: number[]) => {
    b.push(...u32be(data.length));
    for (const ch of type) b.push(ch.charCodeAt(0));
    b.push(...data);
    b.push(0, 0, 0, 0); // CRC — the parser never reads it
  };

  // 13-byte IHDR: width, height, bit depth, colour type, compression, filter, interlace
  chunk('IHDR', [...u32be(800), ...u32be(600), 8, 6, 0, 0, 0]);
  if (text) {
    const payload = [...text.keyword.split('').map(c => c.charCodeAt(0)), 0, ...text.value.split('').map(c => c.charCodeAt(0))];
    chunk('tEXt', payload);
  }
  chunk('IEND', []);
  return new Uint8Array(b);
}

/* ── tests ───────────────────────────────────────────────────── */

describe('sniffFormat', () => {
  it('identifies formats from magic bytes', () => {
    expect(sniffFormat(buildJpegWithExif())).toBe('jpeg');
    expect(sniffFormat(buildPng())).toBe('png');
    expect(sniffFormat(new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]))).toBe('pdf');
    expect(sniffFormat(new Uint8Array([0x47, 0x49, 0x46, 0x38]))).toBe('gif');
    expect(sniffFormat(new Uint8Array([1, 2, 3, 4]))).toBe('unknown');
  });
});

describe('gpsToDecimal', () => {
  it('converts degrees/minutes/seconds', () => {
    expect(gpsToDecimal([41, 2, 0])).toBeCloseTo(41.033333, 5);
    expect(gpsToDecimal([0, 30, 0])).toBeCloseTo(0.5, 5);
  });

  it('returns null for a short or invalid triple', () => {
    expect(gpsToDecimal([41, 2])).toBeNull();
    expect(gpsToDecimal(undefined)).toBeNull();
    expect(gpsToDecimal([41, Number.NaN, 0])).toBeNull();
  });
});

describe('JPEG EXIF', () => {
  const report = parseMetadata(buildJpegWithExif());

  it('reads make and model', () => {
    expect(report.camera).toMatchObject({ make: 'TestCam', model: 'ModelX' });
  });

  it('turns the GPS IFD into signed decimal coordinates and a map link', () => {
    expect(report.gps).not.toBeNull();
    expect(report.gps?.latitude).toBeCloseTo(41, 5);
    expect(report.gps?.longitude).toBeCloseTo(29, 5);
    expect(report.gps?.mapsUrl).toContain('41.000000,29.000000');
  });

  it('records tags with their group', () => {
    expect(report.tags).toEqual(
      expect.arrayContaining([
        { group: 'Image', tag: 'Make', value: 'TestCam' },
        { group: 'Image', tag: 'Model', value: 'ModelX' },
      ]),
    );
  });

  it('does not invent timestamps that are absent', () => {
    expect(report.timestamps).toBeNull();
  });
});

describe('PNG', () => {
  it('reads dimensions and a tEXt chunk', () => {
    const report = parseMetadata(buildPng({ keyword: 'Author', value: 'Jane Doe' }));
    expect(report.format).toBe('png');
    expect(report.width).toBe(800);
    expect(report.height).toBe(600);
    expect(report.tags).toEqual([{ group: 'PNG', tag: 'Author', value: 'Jane Doe' }]);
  });

  it('warns when there is no metadata at all', () => {
    const report = parseMetadata(buildPng());
    expect(report.warnings.join(' ')).toContain('No metadata tags');
  });
});

describe('PDF', () => {
  it('reads the document information dictionary', () => {
    const pdf = new TextEncoder().encode(
      '%PDF-1.7\n<< /Title (Quarterly Report) /Author (Jane Doe) /Producer (LibreOffice 7.6) /CreationDate (D:20240101120000Z) >>',
    );
    const report = parseMetadata(pdf);
    expect(report.format).toBe('pdf');
    expect(report.tags).toEqual(
      expect.arrayContaining([
        { group: 'PDF', tag: 'Title', value: 'Quarterly Report' },
        { group: 'PDF', tag: 'Author', value: 'Jane Doe' },
        { group: 'PDF', tag: 'Producer', value: 'LibreOffice 7.6' },
      ]),
    );
  });

  it('warns when no info dictionary is present', () => {
    const report = parseMetadata(new TextEncoder().encode('%PDF-1.7\n1 0 obj\n<< >>\nendobj\n'));
    expect(report.warnings.join(' ')).toContain('No document-information dictionary');
  });
});

describe('robustness', () => {
  it('never throws on random bytes', () => {
    const random = new Uint8Array(2048);
    for (let i = 0; i < random.length; i++) random[i] = (i * 37 + 11) & 0xff;
    expect(() => parseMetadata(random)).not.toThrow();
    expect(parseMetadata(random).format).toBe('unknown');
  });

  it('does not follow an EXIF offset outside the buffer', () => {
    const tiff = buildTiff();
    // Point IFD0 at a byte past the end of the block.
    tiff[4] = 0xff; tiff[5] = 0xff; tiff[6] = 0xff; tiff[7] = 0x7f;
    const bytes = new Uint8Array([
      0xff, 0xd8, 0xff, 0xe1, ...u16be(2 + 6 + tiff.length),
      0x45, 0x78, 0x69, 0x66, 0x00, 0x00, ...tiff, 0xff, 0xda, 0xff, 0xd9,
    ]);
    expect(() => parseMetadata(bytes)).not.toThrow();
  });

  it('survives a truncated JPEG', () => {
    const truncated = buildJpegWithExif().slice(0, 30);
    expect(() => parseMetadata(truncated)).not.toThrow();
  });
});

describe('metadataToText', () => {
  it('writes a readable report that includes GPS and notes', () => {
    const text = metadataToText(parseMetadata(buildJpegWithExif()), 'photo.jpg');
    expect(text).toContain('MEDIA METADATA');
    expect(text).toContain('File: photo.jpg');
    expect(text).toContain('Latitude:  41');
    expect(text).toContain('[Image] Make: TestCam');
  });
});
