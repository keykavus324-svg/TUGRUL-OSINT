import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {join} from 'node:path';
describe('TUĞRUL footer and local audio',()=>{
 it('does not advertise upstream social accounts',()=>{const code=readFileSync(join(process.cwd(),'src/components/GlobalStatusBar.tsx'),'utf8');expect(code).not.toMatch(/discord\.gg|x\.com\/soulsimplifai|DiscordIcon|XIcon/);expect(code).toContain('href="/privacy"');expect(code).toContain('href="/docs"')});
 it('uses TUĞRUL share text',()=>{expect(readFileSync(join(process.cwd(),'src/components/SharePanel.tsx'),'utf8')).not.toContain('OSIRIS — Global Intelligence Dashboard')});
 it('plays the hosted track without a music panel or YouTube iframe',()=>{const code=readFileSync(join(process.cwd(),'src/components/BackgroundAudio.tsx'),'utf8');expect(code).toContain('src="/videoplayback.mp3"');expect(code).toContain('autoPlay loop');expect(code).not.toMatch(/<iframe|type="file"|tg-audio-panel/);expect(code).toContain("document.addEventListener('pointerdown'");expect(code).toContain("document.removeEventListener('pointerdown'");expect(code).toContain('wanted.current=false');expect(code).toContain('aria-pressed={playing}')});
});
