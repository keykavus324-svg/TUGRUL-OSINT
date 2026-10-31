import {describe,it,expect} from 'vitest';
import {MUSIC_EMBED_URL,MUSIC_WATCH_URL,MUSIC_VIDEO_ID,MUSIC_PLAYLIST_ID} from './music';
describe('user-selected YouTube preset',()=>{
 it('keeps the requested video and playlist ready without file upload',()=>{const watch=new URL(MUSIC_WATCH_URL);expect(watch.searchParams.get('v')).toBe('WtAfwXGd_ms');expect(watch.searchParams.get('list')).toBe(MUSIC_PLAYLIST_ID)});
 it('uses the official privacy-enhanced player with visible controls',()=>{const url=new URL(MUSIC_EMBED_URL);expect(url.hostname).toBe('www.youtube-nocookie.com');expect(url.pathname).toBe(`/embed/${MUSIC_VIDEO_ID}`);expect(url.searchParams.get('list')).toBe(MUSIC_PLAYLIST_ID);expect(url.searchParams.get('controls')).toBe('1');expect(url.searchParams.get('loop')).toBe('1')});
});
