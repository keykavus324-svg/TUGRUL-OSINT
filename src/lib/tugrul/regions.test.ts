import {describe,it,expect} from 'vitest';
import {REGIONS,validSource,readNotes} from './regions';
describe('TUĞRUL research',()=>{
 it('provides valid regional coordinates',()=>{for(const r of REGIONS){expect(Math.abs(r.lat)).toBeLessThanOrEqual(90);expect(Math.abs(r.lng)).toBeLessThanOrEqual(180);expect(r.zoom).toBeGreaterThan(0)}});
 it('rejects executable or invalid source links',()=>{expect(validSource('javascript:alert(1)')).toBe(false);expect(validSource('data:text/html,test')).toBe(false);expect(validSource('garbage')).toBe(false);expect(validSource('https://example.org')).toBe(true)});
 it('handles damaged or unexpected browser storage',()=>{expect(readNotes('{')).toEqual([]);expect(readNotes('{}')).toEqual([]);expect(readNotes('[null,5,{}]')).toEqual([])});
 it('restores sourced notes only',()=>{const note={id:'test',text:'test',source:'https://example.org',createdAt:new Date().toISOString()};expect(readNotes(JSON.stringify([note]))).toEqual([note]);expect(readNotes(JSON.stringify([{...note,source:'javascript:1'}]))).toEqual([])});
});

import {importNotes,mergeNotes,markdownReport} from './regions';
describe('research portability',()=>{
 const note={id:'1',text:'Gözlem',source:'https://example.org',createdAt:'2026-10-30T12:00:00Z'};
 it('imports exported envelopes',()=>expect(importNotes(JSON.stringify({notes:[note]}))).toEqual([note]));
 it('rejects invalid protocols and dates',()=>{expect(()=>importNotes(JSON.stringify([{...note,source:'javascript:1'}]))).toThrow();expect(()=>importNotes(JSON.stringify([{...note,createdAt:'invalid'}]))).toThrow()});
 it('deduplicates IDs including duplicates inside import',()=>expect(mergeNotes([note],[note,{...note,id:'2'},{...note,id:'2'}])).toHaveLength(2));
 it('enforces the 200 note cap',()=>expect(()=>mergeNotes([],Array.from({length:201},(_,i)=>({...note,id:String(i)})))).toThrow());
 it('exports source and verification in readable reports',()=>{expect(markdownReport([note])).toContain(note.source);expect(markdownReport([note])).toContain('doğrulama')});
});
