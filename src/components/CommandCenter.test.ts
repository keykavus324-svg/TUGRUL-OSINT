import {describe,it,expect} from 'vitest';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import {CommandCenter,SignalBrief} from './CommandCenter';
const noop=()=>{};
describe('TUĞRUL command chrome',()=>{
 it('offers an accessible density toggle in both layouts',()=>{const props={layers:0,cameras:0,quakes:0,status:'connecting',onSearch:noop,onLayers:noop,onHome:noop,onSignals:noop,signalsOpen:false,onDensity:noop};expect(renderToStaticMarkup(createElement(CommandCenter,{...props,compact:true}))).toContain('aria-label="Geniş görünümü aç"');expect(renderToStaticMarkup(createElement(CommandCenter,{...props,compact:false}))).toContain('aria-label="Kompakt görünümü aç"')});
 it('renders actual counts and connection state rather than invented activity',()=>{const html=renderToStaticMarkup(createElement(CommandCenter,{layers:5,cameras:123,quakes:0,status:'connecting',onSearch:noop,onLayers:noop,onHome:noop,onSignals:noop,signalsOpen:true}));expect(html).toContain('BAĞLANTI KURULUYOR');expect(html).toContain('123');expect(html).toContain('Yüklenen kaynak verisi');expect(html).toContain('Konum veya koordinat ara')});
 it('does not equate an empty feed with safety',()=>{const html=renderToStaticMarkup(createElement(SignalBrief,{quakes:[],onLocate:noop,onClose:noop}));expect(html).toContain('Boş akış, olay olmadığı anlamına gelmez.')});
 it('uses source links only with safe schemes',()=>{const html=renderToStaticMarkup(createElement(SignalBrief,{quakes:[{id:'q1',lat:39,lng:38,magnitude:4.5,place:'Test',url:'javascript:alert(1)'}],onLocate:noop,onClose:noop}));expect(html).not.toContain('javascript:');expect(html).toContain('M 4.5')});
 it('shows no more than three recent reference records',()=>{const html=renderToStaticMarkup(createElement(SignalBrief,{quakes:Array.from({length:6},(_,i)=>({id:String(i),lat:39,lng:38,magnitude:3,time:1000*i,place:'TEST_RECORD_'+i})),onLocate:noop,onClose:noop}));expect(html).toContain('TEST_RECORD_5');expect(html).not.toContain('TEST_RECORD_0');expect((html.match(/<article/g)||[]).length).toBe(3)});
});
