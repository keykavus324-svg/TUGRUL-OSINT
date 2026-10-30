'use client';

import {useEffect, useRef, useState} from 'react';
import {Music2, Play, Pause, SkipForward, Upload, X, Volume2, VolumeX} from 'lucide-react';

type Track = {name:string;url:string};
const LIMIT=100*1024*1024;

/** Local playback only: chosen files never leave the user's browser. */
export default function BackgroundAudio(){
  const [open,setOpen]=useState(false),[tracks,setTracks]=useState<Track[]>([]),[index,setIndex]=useState(0),[playing,setPlaying]=useState(false),[volume,setVolume]=useState(.3),[muted,setMuted]=useState(false),[error,setError]=useState('');
  const audio=useRef<HTMLAudioElement>(null),picker=useRef<HTMLInputElement>(null),urls=useRef<string[]>([]);
  useEffect(()=>()=>{urls.current.forEach(url=>URL.revokeObjectURL(url))},[]);
  useEffect(()=>{if(audio.current){audio.current.volume=volume;audio.current.muted=muted}},[volume,muted]);
  async function play(){try{await audio.current?.play();setError('')}catch{setPlaying(false);setError('Oynatma başlatılamadı. Dosya biçimini kontrol edip tekrar deneyin.')}}
  function toggle(){if(!tracks.length){picker.current?.click();return}if(playing)audio.current?.pause();else void play()}
  function next(){if(tracks.length>1){setIndex(i=>(i+1)%tracks.length)}else if(audio.current){audio.current.currentTime=0;void play()}}
  function choose(e:React.ChangeEvent<HTMLInputElement>){const files=Array.from(e.target.files||[]);if(!files.length)return;
    if(files.length>30){setError('Bir seferde en fazla 30 parça seçin.');e.target.value='';return}
    if(files.some(f=>f.size>LIMIT||!(f.type.startsWith('audio/')||/\.(mp3|wav|ogg|m4a|aac|flac|opus)$/i.test(f.name)))){setError('Ses dosyası seçin; her dosya en fazla 100 MB olabilir.');e.target.value='';return}
    audio.current?.pause();urls.current.forEach(url=>URL.revokeObjectURL(url));const nextTracks=files.map(f=>({name:f.name.replace(/\.[^.]+$/,''),url:URL.createObjectURL(f)}));urls.current=nextTracks.map(t=>t.url);setTracks(nextTracks);setIndex(0);setPlaying(false);setError('');setOpen(true);e.target.value='';
  }
  return <div className="tg-audio" data-hud>
    <audio ref={audio} src={tracks[index]?.url} loop={tracks.length===1} onLoadedMetadata={()=>{if(tracks.length)void play()}} onPlay={()=>setPlaying(true)} onPause={()=>setPlaying(false)} onEnded={next} onError={()=>{setPlaying(false);setError('Bu ses dosyası tarayıcınızda oynatılamıyor. Başka bir dosya seçin.')}} preload="metadata"/>
    <input type="file" accept="audio/*,.mp3,.wav,.ogg,.m4a,.flac,.opus" multiple hidden ref={picker} onChange={choose} aria-label="Arka plan müziği seç"/>
    {open&&<section className="tg-audio-panel" aria-label="Arka plan müziği"><div className="tg-audio-heading"><span><Music2 size={15}/> OPERASYON FREKANSI</span><button aria-label="Müzik panelini kapat" onClick={()=>setOpen(false)}><X size={16}/></button></div><h3>{tracks[index]?.name||'Kendi müziğin. Kendi atmosferin.'}</h3><p>Elindeki Kurtlar Vadisi parçasını veya başka bir ses dosyasını seç. Dosyalar sunucuya yüklenmez.</p><button className="tg-audio-upload" onClick={()=>picker.current?.click()}><Upload size={14}/>{tracks.length?'Çalma listesini değiştir':'Müzik dosyası seç'}</button>{tracks.length>0&&<><div className="tg-audio-controls"><button aria-label={playing?'Müziği duraklat':'Müziği başlat'} onClick={toggle}>{playing?<Pause size={21}/>:<Play size={21}/>}</button><button aria-label="Sonraki parça" onClick={next}><SkipForward size={17}/></button><span>{index+1} / {tracks.length} · DÖNGÜ</span><button aria-label={muted?'Sesi aç':'Sessize al'} onClick={()=>setMuted(v=>!v)}>{muted?<VolumeX size={17}/>:<Volume2 size={17}/>}</button></div><label className="tg-audio-volume">SES<input aria-label="Müzik ses seviyesi" type="range" min="0" max="1" step=".01" value={volume} onChange={e=>setVolume(Number(e.target.value))}/><span>{Math.round(volume*100)}%</span></label><div className="tg-audio-list">{tracks.map((t,i)=><button key={t.url} className={i===index?'active':''} onClick={()=>{if(i===index){if(!playing)void play()}else setIndex(i)}}><span>{String(i+1).padStart(2,'0')}</span>{t.name}{i===index&&playing&&<Music2 size={12}/>}</button>)}</div></>}{error&&<p className="tg-audio-error" role="alert">{error}</p>}<small>Seçim sayfa yenilendiğinde sıfırlanır. İlk oynatma için dokunmanız gerekebilir.</small></section>}
    <div className="tg-audio-dock"><button aria-label="Müzik panelini aç veya kapat" aria-expanded={open} onClick={()=>setOpen(v=>!v)}><Music2 size={14}/><span>{playing?'MÜZİK ÇALIYOR':'ARKA PLAN MÜZİĞİ'}</span>{playing&&<i/>}</button>{tracks.length>0&&<button aria-label={playing?'Duraklat':'Oynat'} onClick={toggle}>{playing?<Pause size={13}/>:<Play size={13}/>}</button>}</div>
  </div>
}
