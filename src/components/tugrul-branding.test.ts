import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
describe('TUĞRUL footer and local audio',()=>{
 it('does not advertise upstream social accounts',()=>{const code=readFileSync(join(process.cwd(),'src/components/GlobalStatusBar.tsx'),'utf8');expect(code).not.toMatch(/discord\.gg|x\.com\/soulsimplifai|DiscordIcon|XIcon/);expect(code).toContain('href="/privacy"');expect(code).toContain('href="/docs"')});
 it('uses TUĞRUL share text',()=>{expect(readFileSync(join(process.cwd(),'src/components/SharePanel.tsx'),'utf8')).not.toContain('OSIRIS — Global Intelligence Dashboard')});
 it('keeps selected music local with no network player or upload',()=>{const code=readFileSync(join(process.cwd(),'src/components/BackgroundAudio.tsx'),'utf8');expect(code).toContain('URL.createObjectURL(f)');expect(code).toContain('URL.revokeObjectURL');expect(code).not.toMatch(/fetch\(|autoPlay/);expect(code).toContain('onEnded={next}')});
});
