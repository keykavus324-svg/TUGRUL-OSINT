/**
 * TUĞRUL RECON+ — media metadata extractor.
 *
 * ExifTool (Artistic-2.0 / GPL) is the reference implementation; a full port
 * would be tens of thousands of tag definitions. This is the small subset
 * that actually answers an OSINT question:
 *
 *   • where was this photo taken  → GPS IFD → decimal coordinates
 *   • what took it                → Make / Model / LensModel
 *   • when was it taken           → DateTimeOriginal, with the camera clock
 *                                   caveat stated rather than hidden
 *   • was it edited               → Software, last-modified time
 *
 * It is a pure function over a Uint8Array and therefore runs in the browser:
 * the file is parsed locally and never uploaded. Every read is bounds-checked
 * and every loop is capped, because an analyst will inevitably feed it a
 * corrupt or hostile file.
 */

export type MediaFormat = 'jpeg' | 'png' | 'pdf' | 'gif' | 'webp' | 'tiff' | 'unknown';

export interface MetaTag {
  group: string;
  tag: string;
  value: string;
}

export interface GpsLocation {
  latitude: number;
  longitude: number;
  altitude?: number;
  /** Raw camera stamps, kept separate from any inferred time. */
  timestamp?: string;
  mapsUrl: string;
}

export interface MetadataReport {
  format: MediaFormat;
  byteLength: number;
  width: number | null;
  height: number | null;
  tags: MetaTag[];
  gps: GpsLocation | null;
  camera: { make?: string; model?: string; lens?: string; software?: string } | null;
  timestamps: { original?: string; digitized?: string; modified?: string; gps?: string } | null;
  warnings: string[];
}

/* ── byte helpers ────────────────────────────────────────────── */

class Reader {
  constructor(public readonly bytes: Uint8Array) {}

  u8(o: number): number | null {
    return o >= 0 && o < this.bytes.length ? this.bytes[o] : null;
  }

  u16be(o: number): number | null {
    if (o < 0 || o + 2 > this.bytes.length) return null;
    return (this.bytes[o] << 8) | this.bytes[o + 1];
  }

  u16le(o: number): number | null {
    if (o < 0 || o + 2 > this.bytes.length) return null;
    return this.bytes[o] | (this.bytes[o + 1] << 8);
  }

  u32be(o: number): number | null {
    if (o < 0 || o + 4 > this.bytes.length) return null;
    return ((this.bytes[o] << 24) >>> 0) + (this.bytes[o + 1] << 16) + (this.bytes[o + 2] << 8) + this.bytes[o + 3];
  }

  u32le(o: number): number | null {
    if (o < 0 || o + 4 > this.bytes.length) return null;
    return ((this.bytes[o + 3] << 24) >>> 0) + (this.bytes[o + 2] << 16) + (this.bytes[o + 1] << 8) + this.bytes[o];
  }

  /** Bytes as Latin-1, NULs included — PNG text chunks embed one. */
  latin1(o: number, length: number): string {
    const end = Math.min(this.bytes.length, o + length);
    let out = '';
    for (let i = Math.max(0, o); i < end; i++) out += String.fromCharCode(this.bytes[i]);
    return out;
  }

  ascii(o: number, length: number): string {
    const end = Math.min(this.bytes.length, o + length);
    let out = '';
    for (let i = Math.max(0, o); i < end; i++) {
      const b = this.bytes[i];
      if (b === 0) break;
      out += b >= 32 && b < 127 ? String.fromCharCode(b) : ' ';
    }
    return out.trim();
  }
}

/* ── TIFF / EXIF ─────────────────────────────────────────────── */

const TAG_NAMES: Record<number, { group: string; name: string }> = {
  0x0100: { group: 'Image', name: 'ImageWidth' },
  0x0101: { group: 'Image', name: 'ImageHeight' },
  0x010e: { group: 'Image', name: 'ImageDescription' },
  0x010f: { group: 'Image', name: 'Make' },
  0x0110: { group: 'Image', name: 'Model' },
  0x0112: { group: 'Image', name: 'Orientation' },
  0x011a: { group: 'Image', name: 'XResolution' },
  0x011b: { group: 'Image', name: 'YResolution' },
  0x0128: { group: 'Image', name: 'ResolutionUnit' },
  0x0131: { group: 'Image', name: 'Software' },
  0x0132: { group: 'Image', name: 'ModifyDate' },
  0x013b: { group: 'Image', name: 'Artist' },
  0x8298: { group: 'Image', name: 'Copyright' },
  0x8769: { group: 'Image', name: 'ExifIFDPointer' },
  0x8825: { group: 'Image', name: 'GPSInfoIFDPointer' },
  0x829a: { group: 'Exif', name: 'ExposureTime' },
  0x829d: { group: 'Exif', name: 'FNumber' },
  0x8822: { group: 'Exif', name: 'ExposureProgram' },
  0x8827: { group: 'Exif', name: 'ISO' },
  0x9003: { group: 'Exif', name: 'DateTimeOriginal' },
  0x9004: { group: 'Exif', name: 'DateTimeDigitized' },
  0x9201: { group: 'Exif', name: 'ShutterSpeedValue' },
  0x9202: { group: 'Exif', name: 'ApertureValue' },
  0x9209: { group: 'Exif', name: 'Flash' },
  0x920a: { group: 'Exif', name: 'FocalLength' },
  0x9291: { group: 'Exif', name: 'SubSecTimeOriginal' },
  0xa002: { group: 'Exif', name: 'ExifImageWidth' },
  0xa003: { group: 'Exif', name: 'ExifImageHeight' },
  0xa434: { group: 'Exif', name: 'LensModel' },
  0xa430: { group: 'Exif', name: 'CameraOwnerName' },
  0xa431: { group: 'Exif', name: 'BodySerialNumber' },
  0xa433: { group: 'Exif', name: 'LensMake' },
  0x0000: { group: 'GPS', name: 'GPSVersionID' },
  0x0001: { group: 'GPS', name: 'GPSLatitudeRef' },
  0x0002: { group: 'GPS', name: 'GPSLatitude' },
  0x0003: { group: 'GPS', name: 'GPSLongitudeRef' },
  0x0004: { group: 'GPS', name: 'GPSLongitude' },
  0x0005: { group: 'GPS', name: 'GPSAltitudeRef' },
  0x0006: { group: 'GPS', name: 'GPSAltitude' },
  0x0007: { group: 'GPS', name: 'GPSTimeStamp' },
  0x001d: { group: 'GPS', name: 'GPSDateStamp' },
  0x0010: { group: 'GPS', name: 'GPSImgDirectionRef' },
  0x0011: { group: 'GPS', name: 'GPSImgDirection' },
};

interface TiffContext {
  reader: Reader;
  /** Offset of the TIFF header within the file. */
  base: number;
  little: boolean;
  tags: MetaTag[];
  warnings: string[];
  gps: {
    latRef?: string;
    lonRef?: string;
    lat?: number[];
    lon?: number[];
    altitude?: number;
    timestamp?: string;
    dateStamp?: string;
  };
}

const TYPE_SIZE: Record<number, number> = {
  1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8,
};

/** A cap on every list and recursion. A malformed file must not hang a tab. */
const MAX_ENTRIES = 400;
const MAX_DEPTH = 4;

function readRational(ctx: TiffContext, offset: number, signed: boolean): number | null {
  const { reader, base, little } = ctx;
  const numerator = little ? reader.u32le(base + offset) : reader.u32be(base + offset);
  const denominator = little ? reader.u32le(base + offset + 4) : reader.u32be(base + offset + 4);
  if (numerator === null || denominator === null || denominator === 0) return null;
  const value = numerator / denominator;
  return signed && numerator > 0x7fffffff ? -(0x100000000 - numerator) / denominator : value;
}

/** Decode one IFD entry into a string (or numbers for GPS coordinate tags). */
function readEntryValue(ctx: TiffContext, entryOffset: number): { tag: number; type: number; count: number; value: string | number[] | null } | null {
  const { reader, base, little } = ctx;
  const tag = little ? reader.u16le(base + entryOffset) : reader.u16be(base + entryOffset);
  const type = little ? reader.u16le(base + entryOffset + 2) : reader.u16be(base + entryOffset + 2);
  const count = little ? reader.u32le(base + entryOffset + 4) : reader.u32be(base + entryOffset + 4);
  if (tag === null || type === null || count === null) return null;
  if (count > 4096) return { tag, type, count, value: null };

  const size = TYPE_SIZE[type];
  if (!size) return { tag, type, count, value: null };
  const total = size * count;
  const valueOffset = total <= 4
    ? entryOffset + 8
    : (little ? reader.u32le(base + entryOffset + 8) : reader.u32be(base + entryOffset + 8));
  if (valueOffset === null) return null;

  const readAt = base + valueOffset;
  if (readAt < 0 || readAt > reader.bytes.length) return { tag, type, count, value: null };

  if (type === 2) return { tag, type, count, value: reader.ascii(readAt, count) };

  const values: number[] = [];
  for (let i = 0; i < Math.min(count, 64); i++) {
    const at = readAt + i * size;
    let v: number | null = null;
    switch (type) {
      case 1: case 7: v = reader.u8(at); break;
      case 3: v = little ? reader.u16le(at) : reader.u16be(at); break;
      case 4: v = little ? reader.u32le(at) : reader.u32be(at); break;
      case 8: v = little ? reader.u16le(at) : reader.u16be(at); break;
      case 9: v = little ? reader.u32le(at) : reader.u32be(at); break;
      case 5: case 10: v = readRational(ctx, at - base, type === 10); break;
      case 11: v = little ? reader.u32le(at) : reader.u32be(at); break;
      case 12: v = readRational(ctx, at - base, false); break;
      default: v = null;
    }
    if (v === null) continue;
    values.push(v);
  }
  return { tag, type, count, value: values };
}

function formatValue(entry: { type: number; value: string | number[] | null }): string | null {
  if (entry.value === null) return null;
  if (typeof entry.value === 'string') return entry.value || null;
  if (!entry.value.length) return null;
  if (entry.type === 5 || entry.type === 10) {
    return entry.value.map(v => (Number.isInteger(v) ? String(v) : v.toFixed(4))).join(', ');
  }
  return entry.value.join(', ');
}

/** Degrees + minutes/60 + seconds/3600 from the three GPS rationals. */
export function gpsToDecimal(parts: number[] | undefined): number | null {
  if (!parts || parts.length < 3) return null;
  const [deg, min, sec] = parts;
  if (![deg, min, sec].every(Number.isFinite)) return null;
  return deg + min / 60 + sec / 3600;
}

function parseIfd(ctx: TiffContext, ifdOffset: number, depth: number): void {
  if (depth > MAX_DEPTH) return;
  const { reader, base, little } = ctx;
  const count = little ? reader.u16le(base + ifdOffset) : reader.u16be(base + ifdOffset);
  if (count === null || count === 0 || count > MAX_ENTRIES) return;

  for (let i = 0; i < count; i++) {
    const entryOffset = ifdOffset + 2 + i * 12;
    const entry = readEntryValue(ctx, entryOffset);
    if (!entry) continue;

    // Sub-IFD pointers are navigation, not reportable metadata.
    if (entry.tag === 0x8769 && Array.isArray(entry.value) && entry.value.length) {
      parseIfd(ctx, entry.value[0], depth + 1);
      continue;
    }
    if (entry.tag === 0x8825 && Array.isArray(entry.value) && entry.value.length) {
      parseIfd(ctx, entry.value[0], depth + 1);
      continue;
    }
    if (entry.tag === 0xa005 && Array.isArray(entry.value) && entry.value.length) {
      parseIfd(ctx, entry.value[0], depth + 1);
      continue;
    }

    const meta = TAG_NAMES[entry.tag];
    if (!meta) continue;

    // GPS coordinate tags keep their raw rationals for the decimal conversion.
    if (meta.group === 'GPS' && Array.isArray(entry.value)) {
      const nums = entry.value as number[];
      if (entry.tag === 0x0002) ctx.gps.lat = nums;
      if (entry.tag === 0x0004) ctx.gps.lon = nums;
      if (entry.tag === 0x0006) ctx.gps.altitude = nums[0];
    }

    const value = formatValue(entry);
    if (!value) continue;

    if (meta.group === 'GPS') {
      if (entry.tag === 0x0001) ctx.gps.latRef = value.toUpperCase();
      if (entry.tag === 0x0003) ctx.gps.lonRef = value.toUpperCase();
      if (entry.tag === 0x0007) ctx.gps.timestamp = value;
      if (entry.tag === 0x001d) ctx.gps.dateStamp = value;
    }

    // Prefer a printable form for the common timestamp tag.
    ctx.tags.push({ group: meta.group, tag: meta.name, value });
  }
}

/** Locate and parse the TIFF block that carries EXIF. */
function parseTiff(ctx: TiffContext): void {
  const { reader, base } = ctx;
  const order = reader.ascii(base, 2);
  if (order !== 'II' && order !== 'MM') {
    ctx.warnings.push('EXIF block has an unknown byte-order mark.');
    return;
  }
  ctx.little = order === 'II';
  const magic = ctx.little ? reader.u16le(base + 2) : reader.u16be(base + 2);
  if (magic !== 42) {
    ctx.warnings.push('EXIF block is not a valid TIFF structure.');
    return;
  }
  const ifd0 = ctx.little ? reader.u32le(base + 4) : reader.u32be(base + 4);
  if (ifd0 === null) {
    ctx.warnings.push('EXIF block has no IFD0 offset.');
    return;
  }
  parseIfd(ctx, ifd0, 0);
}

/* ── JPEG ────────────────────────────────────────────────────── */

function parseJpeg(reader: Reader, report: MetadataReport): void {
  let offset = 2;
  const bytes = reader.bytes;

  while (offset < bytes.length - 1) {
    if (bytes[offset] !== 0xff) {
      offset += 1;
      continue;
    }
    const marker = bytes[offset + 1];
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      offset += 2;
      continue;
    }
    if (marker === 0xd9 || marker === 0xda) break; // EOI / start of scan

    const length = reader.u16be(offset + 2);
    if (length === null || length < 2) break;
    const segmentStart = offset + 4;
    const segmentEnd = offset + 2 + length;

    // EXIF APP1
    if (marker === 0xe1 && reader.ascii(segmentStart, 4) === 'Exif') {
      const tiffBase = segmentStart + 6; // "Exif\0\0"
      const ctx: TiffContext = {
        reader,
        base: tiffBase,
        little: true,
        tags: report.tags,
        warnings: report.warnings,
        gps: {},
      };
      parseTiff(ctx);
      finaliseGps(ctx, report);
    }

    // Start-of-frame → dimensions
    if ([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker)) {
      const height = reader.u16be(segmentStart + 1);
      const width = reader.u16be(segmentStart + 3);
      if (width && height) {
        report.width = width;
        report.height = height;
      }
    }

    offset = segmentEnd;
  }
}

function finaliseGps(ctx: TiffContext, report: MetadataReport): void {
  const lat = gpsToDecimal(ctx.gps.lat);
  const lon = gpsToDecimal(ctx.gps.lon);
  if (lat === null || lon === null) return;

  // A camera that never got a fix writes 0,0 — the Gulf of Guinea.
  if (lat === 0 && lon === 0) {
    report.warnings.push('GPS tags are present but zeroed; the camera had no fix.');
    return;
  }

  const signedLat = ctx.gps.latRef === 'S' ? -Math.abs(lat) : Math.abs(lat);
  const signedLon = ctx.gps.lonRef === 'W' ? -Math.abs(lon) : Math.abs(lon);
  if (Math.abs(signedLat) > 90 || Math.abs(signedLon) > 180) {
    report.warnings.push('GPS coordinates are outside the valid range and were discarded.');
    return;
  }

  report.gps = {
    latitude: Number(signedLat.toFixed(6)),
    longitude: Number(signedLon.toFixed(6)),
    ...(ctx.gps.altitude !== undefined ? { altitude: Math.round(ctx.gps.altitude * 10) / 10 } : {}),
    ...(ctx.gps.dateStamp && ctx.gps.timestamp
      ? { timestamp: `${ctx.gps.dateStamp} ${ctx.gps.timestamp} UTC` }
      : {}),
    mapsUrl: `https://www.google.com/maps?q=${signedLat.toFixed(6)},${signedLon.toFixed(6)}`,
  };
}

/* ── PNG ─────────────────────────────────────────────────────── */

function parsePng(reader: Reader, report: MetadataReport): void {
  let offset = 8;
  while (offset + 8 <= reader.bytes.length && report.tags.length < 300) {
    const length = reader.u32be(offset);
    if (length === null || length > 10_000_000) break;
    const type = reader.ascii(offset + 4, 4);
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    if (dataEnd + 4 > reader.bytes.length) break;

    if (type === 'IHDR') {
      report.width = reader.u32be(dataStart);
      report.height = reader.u32be(dataStart + 4);
    } else if (type === 'tEXt') {
      const raw = reader.latin1(dataStart, length);
      const sep = raw.indexOf('\u0000');
      const keyword = (sep >= 0 ? raw.slice(0, sep) : raw.split(' ')[0]) || 'Text';
      const text = sep >= 0 ? raw.slice(sep + 1).trim() : '';
      if (text) report.tags.push({ group: 'PNG', tag: keyword, value: text.slice(0, 500) });
    } else if (type === 'iTXt') {
      // keyword \0 compressionFlag \0 compressionMethod \0 lang \0 translated \0 text
      const parts = reader.latin1(dataStart, length).split('\u0000');
      const keyword = parts[0] || 'Text';
      const text = parts.slice(5).join('\u0000').trim();
      if (text) report.tags.push({ group: 'PNG', tag: keyword, value: text.slice(0, 500) });
    } else if (type === 'zTXt') {
      report.warnings.push('Compressed PNG text chunk skipped (browser-safe decompression is out of scope).');
    } else if (type === 'eXIf') {
      // The PNG spec stores the TIFF block directly, but some encoders keep
      // the JPEG-style `Exif\0\0` prefix. Accept both.
      const prefixed = reader.ascii(dataStart, 4) === 'Exif';
      const ctx: TiffContext = {
        reader,
        base: prefixed ? dataStart + 6 : dataStart,
        little: true,
        tags: report.tags,
        warnings: report.warnings,
        gps: {},
      };
      parseTiff(ctx);
      finaliseGps(ctx, report);
    } else if (type === 'IEND') {
      break;
    }

    offset = dataEnd + 4; // + CRC
  }
}

/* ── PDF ─────────────────────────────────────────────────────── */

const PDF_INFO: Array<[RegExp, string]> = [
  [/\/Title\s*\(([^)]{0,200})\)/, 'Title'],
  [/\/Author\s*\(([^)]{0,200})\)/, 'Author'],
  [/\/Creator\s*\(([^)]{0,200})\)/, 'Creator'],
  [/\/Producer\s*\(([^)]{0,200})\)/, 'Producer'],
  [/\/CreationDate\s*\((?:D:)?([0-9Z+'\-]{0,40})\)/, 'CreationDate'],
  [/\/ModDate\s*\((?:D:)?([0-9Z+'\-]{0,40})\)/, 'ModDate'],
  [/\/Subject\s*\(([^)]{0,300})\)/, 'Subject'],
  [/\/Keywords\s*\(([^)]{0,300})\)/, 'Keywords'],
];

function parsePdf(reader: Reader, report: MetadataReport): void {
  const prefix = reader.ascii(0, Math.min(reader.bytes.length, 64_000));
  for (const [pattern, label] of PDF_INFO) {
    const match = prefix.match(pattern);
    if (!match || !match[1]) continue;
    report.tags.push({ group: 'PDF', tag: label, value: match[1].replace(/\\([()\\])/g, '$1').slice(0, 300) });
  }
  if (!report.tags.length) report.warnings.push('No document-information dictionary found in the first 64 KB.');
  report.warnings.push('PDF metadata may be inside a compressed object stream; only plain-text info was read.');
}

/* ── entry point ─────────────────────────────────────────────── */

/** Format sniffing from the magic bytes, not the extension. */
export function sniffFormat(bytes: Uint8Array): MediaFormat {
  const sig = (i: number) => bytes[i] ?? -1;
  if (sig(0) === 0xff && sig(1) === 0xd8 && sig(2) === 0xff) return 'jpeg';
  if (sig(0) === 0x89 && sig(1) === 0x50 && sig(2) === 0x4e && sig(3) === 0x47) return 'png';
  if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) return 'pdf';
  if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) return 'gif';
  if (bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
      bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) return 'webp';
  if ((bytes[0] === 0x49 && bytes[1] === 0x49 && bytes[2] === 0x2a && bytes[3] === 0x00) ||
      (bytes[0] === 0x4d && bytes[1] === 0x4d && bytes[2] === 0x00 && bytes[3] === 0x2a)) return 'tiff';
  return 'unknown';
}

/**
 * Parse metadata from a file’s bytes.
 *
 * Never throws: a corrupt file produces `format: 'unknown'` and a warning, so
 * a failed parse cannot take the panel down with it.
 */
export function parseMetadata(bytes: Uint8Array): MetadataReport {
  const reader = new Reader(bytes);
  const report: MetadataReport = {
    format: sniffFormat(bytes),
    byteLength: bytes.length,
    width: null,
    height: null,
    tags: [],
    gps: null,
    camera: null,
    timestamps: null,
    warnings: [],
  };

  try {
    if (report.format === 'jpeg') parseJpeg(reader, report);
    else if (report.format === 'png') parsePng(reader, report);
    else if (report.format === 'pdf') parsePdf(reader, report);
    else if (report.format === 'tiff') {
      const ctx: TiffContext = { reader, base: 0, little: true, tags: report.tags, warnings: report.warnings, gps: {} };
      parseTiff(ctx);
      finaliseGps(ctx, report);
    } else {
      report.warnings.push('Unsupported format. JPEG, PNG, TIFF and PDF are parsed; GIF/WebP metadata is not.');
    }
  } catch (e) {
    report.warnings.push(`Parser stopped on a malformed file: ${e instanceof Error ? e.message : 'unknown error'}`);
  }

  const tag = (group: string, name: string) => report.tags.find(t => t.group === group && t.tag === name)?.value;
  const make = tag('Image', 'Make');
  const model = tag('Image', 'Model');
  const lens = tag('Exif', 'LensModel');
  const software = tag('Image', 'Software');
  if (make || model || lens || software) {
    report.camera = {
      ...(make ? { make } : {}),
      ...(model ? { model } : {}),
      ...(lens ? { lens } : {}),
      ...(software ? { software } : {}),
    };
  }

  const original = tag('Exif', 'DateTimeOriginal');
  const digitized = tag('Exif', 'DateTimeDigitized');
  const modified = tag('Image', 'ModifyDate');
  if (original || digitized || modified || report.gps?.timestamp) {
    report.timestamps = {
      ...(original ? { original } : {}),
      ...(digitized ? { digitized } : {}),
      ...(modified ? { modified } : {}),
      ...(report.gps?.timestamp ? { gps: report.gps.timestamp } : {}),
    };
  }

  if (software) {
    report.warnings.push(`Software tag present (${software}) — the file passed through an editor.`);
  }
  if (report.timestamps?.original) {
    report.warnings.push('Camera timestamps are set by the device and can be wrong or deliberately altered; treat them as a lead, not proof.');
  }
  if (!report.tags.length && report.format !== 'unknown') {
    report.warnings.push('No metadata tags were found. Many platforms strip EXIF on upload.');
  }

  // Stable order makes the UI and the JSON export comparable between runs.
  report.tags.sort((a, b) => a.group.localeCompare(b.group) || a.tag.localeCompare(b.tag));
  return report;
}

/** The report as a flat text block, for the export button. */
export function metadataToText(report: MetadataReport, filename?: string): string {
  const lines = [
    'TUĞRUL RECON+ — MEDIA METADATA',
    `File: ${filename || '(unnamed)'}`,
    `Format: ${report.format.toUpperCase()} · ${report.byteLength} bytes`,
    report.width && report.height ? `Dimensions: ${report.width}×${report.height}` : 'Dimensions: unknown',
    '',
  ];
  if (report.gps) {
    lines.push(
      'GPS:',
      `  Latitude:  ${report.gps.latitude}`,
      `  Longitude: ${report.gps.longitude}`,
      ...(report.gps.altitude !== undefined ? [`  Altitude:  ${report.gps.altitude} m`] : []),
      ...(report.gps.timestamp ? [`  Timestamp: ${report.gps.timestamp}`] : []),
      `  Map: ${report.gps.mapsUrl}`,
      '',
    );
  }
  if (report.tags.length) {
    lines.push('Tags:');
    for (const t of report.tags) lines.push(`  [${t.group}] ${t.tag}: ${t.value}`);
    lines.push('');
  }
  if (report.warnings.length) {
    lines.push('Notes:');
    for (const w of report.warnings) lines.push(`  - ${w}`);
  }
  return lines.join('\n');
}
