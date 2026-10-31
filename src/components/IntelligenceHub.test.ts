import {it,expect} from 'vitest';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import IntelligenceHub from './IntelligenceHub';
it('adds only a compact launcher, with the suite closed by default',()=>{const html=renderToStaticMarkup(createElement(IntelligenceHub,{quakes:[],onFlyTo:()=>{}}));expect(html).toContain('aria-label="Araç merkezini aç"');expect(html).toContain('aria-expanded="false"');expect(html).not.toContain('role="dialog"');expect(html).not.toContain('<iframe')});
