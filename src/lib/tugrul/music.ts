/** User-selected preset. Playback stays in the official YouTube player. */
export const MUSIC_VIDEO_ID = 'WtAfwXGd_ms';
export const MUSIC_PLAYLIST_ID = 'PLqjYw0NUCsdqIRE_HMy0aXpYq3bdrg0p7';
export const MUSIC_WATCH_URL = `https://www.youtube.com/watch?v=${MUSIC_VIDEO_ID}&list=${MUSIC_PLAYLIST_ID}&index=2`;
export const MUSIC_EMBED_URL = `https://www.youtube-nocookie.com/embed/${MUSIC_VIDEO_ID}?${new URLSearchParams({list:MUSIC_PLAYLIST_ID,autoplay:'1',loop:'1',controls:'1',playsinline:'1',rel:'0'})}`;
