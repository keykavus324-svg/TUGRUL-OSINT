/** TUĞRUL additions. Coordinates are reference locations, not live events. */
export const REGIONS = [
  { name: 'Türkiye', lat: 39, lng: 35, zoom: 5.5 },
  { name: 'Elazığ', lat: 38.6748, lng: 39.2225, zoom: 10 },
  { name: 'İstanbul Boğazı', lat: 41.12, lng: 29.06, zoom: 10 },
  { name: 'Çanakkale Boğazı', lat: 40.2, lng: 26.4, zoom: 10 },
  { name: 'Doğu Akdeniz', lat: 34.8, lng: 33.5, zoom: 6 },
  { name: 'Karadeniz', lat: 43, lng: 34, zoom: 5.5 },
] as const;
export type ResearchNote = { id: string; text: string; source: string; createdAt: string };
export function validSource(value: string): boolean {
  try { return ['https:', 'http:'].includes(new URL(value).protocol); } catch { return false; }
}
export function readNotes(raw: string | null): ResearchNote[] {
  try { const data: unknown = JSON.parse(raw || '[]');
    return Array.isArray(data) ? data.filter((n): n is ResearchNote => !!n && typeof n === 'object' && typeof n.id === 'string' && typeof n.text === 'string' && typeof n.source === 'string' && validSource(n.source) && typeof n.createdAt === 'string').slice(0, 200) : [];
  } catch { return []; }
}

export function importNotes(raw: string): ResearchNote[] {
  if (raw.length > 2_000_000) throw new Error('Dosya 2 MB sınırını aşıyor.');
  const value = JSON.parse(raw);
  const entries = Array.isArray(value) ? value : value?.notes;
  if (!Array.isArray(entries)) throw new Error('JSON bir bulgu listesi içermiyor.');
  const notes = readNotes(JSON.stringify(entries));
  if (notes.length !== entries.length || notes.some(n => n.text.length > 4000 || n.id.length > 100 || n.source.length > 2048 || !Number.isFinite(Date.parse(n.createdAt)))) throw new Error('Dosyada geçersiz veya sınırları aşan bulgular var.');
  return notes;
}
export function mergeNotes(current: ResearchNote[], incoming: ResearchNote[]): ResearchNote[] {
  const merged = [...current];
  const ids = new Set(current.map(n=>n.id));
  for (const note of incoming) if (!ids.has(note.id)) { merged.push(note); ids.add(note.id); }
  if (merged.length > 200) throw new Error('Dosya limiti 200 bulgudur.');
  return merged;
}
export function markdownReport(notes: ResearchNote[]): string {
  return '# TUĞRUL OSİNT · Araştırma raporu\n\nAnalist notları · Bağımsız doğrulama gerektirir.\n\n' + notes.map((n,i)=>`## Bulgu ${i+1}\n\n${n.text}\n\nKaynak: ${n.source}\n\nKayıt: ${n.createdAt}\n`).join('\n---\n\n');
}
