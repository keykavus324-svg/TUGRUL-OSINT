'use client';

import {useEffect, useRef, useState} from 'react';
import {Volume2, VolumeX} from 'lucide-react';

/** Hosted soundtrack. No player panel, uploads or third-party embeds. */
export default function BackgroundAudio(){
  const audio = useRef<HTMLAudioElement>(null);
  const wanted = useRef(true);
  const [playing,setPlaying] = useState(false);
  const [failed,setFailed] = useState(false);

  useEffect(()=>{
    const player = audio.current;
    if(!player)return;
    let mounted = true;
    player.volume = 0.3;
    const start = ()=>{
      if(!mounted || !wanted.current || !player.paused)return;
      // Autoplay may be denied. The next real page interaction retries it.
      void player.play().catch(()=>{});
    };
    const gesture = (event: Event)=>{
      if(event.target instanceof Element && event.target.closest('[data-audio-control]'))return;
      start();
    };
    document.addEventListener('pointerdown',gesture,true);
    document.addEventListener('keydown',gesture,true);
    player.addEventListener('canplay',start);
    start();
    return ()=>{
      mounted=false;
      document.removeEventListener('pointerdown',gesture,true);
      document.removeEventListener('keydown',gesture,true);
      player.removeEventListener('canplay',start);
      player.pause();
    };
  },[]);

  function toggle(){
    const player=audio.current;
    if(!player)return;
    if(!player.paused){wanted.current=false;player.pause();return;}
    wanted.current=true;
    setFailed(false);
    void player.play().catch(()=>setFailed(true));
  }
  const label=failed?'Müzik oynatılamadı; yeniden dene':playing?'Arka plan müziğini kapat':'Arka plan müziğini başlat';
  return <>
    <audio ref={audio} src="/videoplayback.mp3" autoPlay loop preload="auto" onPlaying={()=>{setPlaying(true);setFailed(false)}} onPause={()=>setPlaying(false)} onError={()=>{setPlaying(false);setFailed(true)}}/>
    <button className="tg-sound-toggle" data-audio-control type="button" title={label} aria-label={label} aria-pressed={playing} onClick={toggle}>
      {playing?<Volume2 size={16}/>:<VolumeX size={16}/>}
    </button>
  </>;
}
