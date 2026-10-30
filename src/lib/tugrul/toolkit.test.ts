import {describe,it,expect} from 'vitest';
import {domainName,ipv4,searchQuery,parseCoordinate,distanceKm,bearing,dms,extractIndicators,analyzeUrl,parseToolkit,mergeToolkit,toolkitReport,SOURCE_LIBRARY,type ToolkitStore} from './toolkit';
const store:ToolkitStore={watch:[{id:'w1',value:'example.org',category:'domain',note:'Analist notu',createdAt:'2026-10-30T10:00:00Z'}],timeline:[{id:'t1',title:'Test olay',at:'2026-10-30T08:00:00Z',source:'https://example.org/news',confidence:'unverified',createdAt:'2026-10-30T10:00:00Z'}]};
describe('domain and network inputs',()=>{
 it.each(['example.org','https://EXAMPLE.ORG/report','example.org.'])('normalizes %s',s=>expect(domainName(s)).toBe('example.org'));
 it.each(['localhost','http://127.0.0.1','https://user:pass@example.org','javascript:alert(1)','https://example.org:8123','-bad.org','good..org'])('rejects %s',s=>expect(()=>domainName(s)).toThrow());
 it.each(['0.0.0.0','8.8.8.8','255.255.255.255'])('validates IPv4 %s',s=>expect(ipv4(s)).toBe(true));
 it.each(['256.0.0.1','1.2.3','1.2.3.4.5','01.1.1.1','1.2.3.-1'])('rejects IPv4 %s',s=>expect(ipv4(s)).toBe(false));
});
describe('research query',()=>{
 const p={term:'Elazığ rapor',site:'afad.gov.tr',type:'pdf',after:'2026-01-01',before:'2026-10-30',exact:true};
 it('builds source, file and date filters',()=>expect(searchQuery(p)).toBe('"Elazığ rapor" site:afad.gov.tr filetype:pdf after:2026-01-01 before:2026-10-30'));
 it('rejects missing topic',()=>expect(()=>searchQuery({...p,term:' '})).toThrow());
 it('rejects reversed dates',()=>expect(()=>searchQuery({...p,after:'2026-12-01'})).toThrow());
 it('rejects non-calendar dates',()=>expect(()=>searchQuery({...p,after:'2026-02-30'})).toThrow());
 it('rejects unsupported file types',()=>expect(()=>searchQuery({...p,type:'exe'})).toThrow());
});
describe('geographic tools',()=>{
 it('accepts decimal coordinates',()=>expect(parseCoordinate('38.6748, 39.2225')).toEqual({lat:38.6748,lng:39.2225}));
 it.each(['91,0','0,-181','','1,2,3','1e4,2','0x1,2'])('rejects %s',s=>expect(()=>parseCoordinate(s)).toThrow());
 it('measures zero distance',()=>expect(distanceKm({lat:0,lng:0},{lat:0,lng:0})).toBe(0));
 it('measures one equatorial degree',()=>expect(distanceKm({lat:0,lng:0},{lat:0,lng:1})).toBeCloseTo(111.195,2));
 it('handles antipodal points without NaN',()=>expect(distanceKm({lat:0,lng:0},{lat:0,lng:180})).toBeCloseTo(20015.087,2));
 it('calculates east bearing',()=>expect(bearing({lat:0,lng:0},{lat:0,lng:1})).toBeCloseTo(90));
 it('formats hemispheres',()=>expect(dms(-38.5,true)).toBe('38° 30′ 0.00″ S'));
});
describe('local indicator / URL processing',()=>{
 it('normalizes defanged indicators and deduplicates',()=>{const v=extractIndicators('hxxps://example[.]org/a 8.8.8.8 8.8.8.8 300.1.1.1 '+ 'a'.repeat(64));expect(v.urls).toEqual(['https://example.org/a']);expect(v.ips).toEqual(['8.8.8.8']);expect(v.domains).toContain('example.org');expect(v.hashes).toEqual(['a'.repeat(64)])});
 it('caps each output bucket',()=>expect(extractIndicators(Array.from({length:220},(_,i)=>`https://d${i}.org`).join(' ')).urls).toHaveLength(200));
 it('rejects oversized text',()=>expect(()=>extractIndicators('a'.repeat(100001))).toThrow());
 it('removes tracker parameters and fragment, retains content query',()=>expect(analyzeUrl('https://example.org/a?q=test&utm_source=x&fbclid=a#part').clean).toBe('https://example.org/a?q=test'));
 it.each(['javascript:alert(1)','https://u:p@example.org/'])('rejects unsafe URL %s',s=>expect(()=>analyzeUrl(s)).toThrow());
});
describe('local dossier import and export',()=>{
 it('roundtrips a validated store',()=>expect(parseToolkit(JSON.stringify({data:store}))).toEqual(store));
 it('does not retain extra imported fields',()=>{const v=JSON.parse(JSON.stringify(store));v.watch[0].secret='ignore';expect(parseToolkit(JSON.stringify(v))).toEqual(store)});
 it('rejects invalid source scheme',()=>{const v=JSON.parse(JSON.stringify(store));v.timeline[0].source='javascript:alert(1)';expect(()=>parseToolkit(JSON.stringify(v))).toThrow()});
 it('rejects URL credentials',()=>{const v=JSON.parse(JSON.stringify(store));v.timeline[0].source='https://user:pass@example.org';expect(()=>parseToolkit(JSON.stringify(v))).toThrow()});
 it('rejects duplicate ids',()=>expect(()=>parseToolkit(JSON.stringify({...store,watch:[store.watch[0],store.watch[0]]}))).toThrow());
 it('rejects oversized backup',()=>expect(()=>parseToolkit('a'.repeat(1000001))).toThrow());
 it('rejects record overflow',()=>expect(()=>parseToolkit(JSON.stringify({...store,watch:Array(201).fill(store.watch[0])}))).toThrow());
 it('rejects corrupted dates',()=>{const v=JSON.parse(JSON.stringify(store));v.timeline[0].at='not a date';expect(()=>parseToolkit(JSON.stringify(v))).toThrow()});
 it('rejects invalid IP targets',()=>{const v=JSON.parse(JSON.stringify(store));v.watch[0].category='ip';expect(()=>parseToolkit(JSON.stringify(v))).toThrow()});
 it('merges without duplicates',()=>expect(mergeToolkit(store,store)).toEqual(store));
 it('merges new events',()=>expect(mergeToolkit(store,{watch:[],timeline:[{...store.timeline[0],id:'t2'}]}).timeline).toHaveLength(2));
 it('produces an honest source-linked report',()=>{const text=toolkitReport(store);expect(text).toContain('https://example.org/news');expect(text).toContain('Teyit bekliyor');expect(text).toContain('otomatik takip/uyarı yapmaz')});
 it('includes 26 HTTPS source references',()=>{expect(SOURCE_LIBRARY).toHaveLength(26);expect(SOURCE_LIBRARY.every(s=>new URL(s[2]).protocol==='https:')).toBe(true)});
});
