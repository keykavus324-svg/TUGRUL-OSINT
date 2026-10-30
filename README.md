# TUĞRUL OSİNT

**Osiris kaynak kodu üzerine geliştirilen Türkiye odaklı OSINT platformu.** Bağımsız bir maket değil: Osiris’in Next.js uygulaması, MapLibre haritası, katmanları, API rotaları ve araçları temel alınmıştır.

## Kaynak ve lisans

Temel: [simplifaisoul/osiris](https://github.com/simplifaisoul/osiris), commit `99f542da645f4e3cbe895d20ea605d1cef2e573c`. Orijinal MIT lisansı `LICENSE` içinde korunmuştur. İthalat ve değişiklik kaydı: [UPSTREAM.md](UPSTREAM.md). Orijinal özellik ve sağlayıcı belgeleri: [Osiris README](docs/OSIRIS-UPSTREAM.md).

## Çalıştırma

Node.js 22+.

```sh
npm ci
npm run dev -- --hostname 0.0.0.0 --port 3000
```

```sh
npm test
npx tsc --noEmit
npm run build
npm start -- --hostname 0.0.0.0 --port 3000
```

## Osiris üzerine eklenenler

- TUĞRUL OSİNT başlığı ve açılış kimliği, Türkçe sayfa metaverisi.
- Otomatik IP konumlandırması yerine Türkiye başlangıç odağı.
- Haritaya entegre **TUĞRUL Çalışma Alanı**: Türkiye, Elazığ, İstanbul/Çanakkale boğazları, Doğu Akdeniz ve Karadeniz kısayolları.
- Kaynak URL’si zorunlu analist notları, yerel kalıcı dosya, kayıt kaldırma, JSON rapor indirme.
- Güvenli kaynak protokolü ve bozuk tarayıcı kaydı kontrolleri, ek testler.
- Upstream ziyaretçi/IP analitiğinin kaldırılması.
- Nominatim istek aralığında erken uyanan zamanlayıcılara karşı düzeltme.

## Sınırlar

Tüm arayüz henüz Türkçeleştirilmedi. Upstream modüller korunmuştur; her modülün canlı çalıştığı iddia edilmez. Harita altlıkları ve canlı sağlayıcılar internet erişimine bağlıdır. Bu geliştirme ortamında yalnızca belirli ağ adreslerine erişilebildiği için dış harita/veri servisleri engellenebilir. Örnek veriyle canlıymış gibi doldurma yapılmaz.

Gerekli anahtarlar için `.env.example`, Docker için `DOCKER.md` dosyasına bakın. Bazı RECON işlevleri ayrı tarayıcı servisi veya sağlayıcı anahtarları gerektirir. Yalnızca yetkiniz olan sistemlerde kullanın. Anahtarları Git’e eklemeyin.

Araştırma notları yalnızca tarayıcının localStorage alanında saklanır; kullanıcı hesabı, şifreli delil deposu veya ekip senkronizasyonu değildir. Hassas veri saklamayın. Analist notları doğrulanmış olay sayılmaz. Platform acil durum karar sistemi değildir.

## v0.2 araştırma deneyimi

Sekmeli araştırma merkezi, resmi kaynak rehberi, kaynak alanı sayaçları, dosya içi Türkçe arama, güvenli JSON içe aktarma (2 MB / 200 bulgu), kimlik bazlı tekrar önleme ve Markdown raporları eklendi. Ctrl/Cmd+J araştırma merkezini açar; Escape kapatır. Kaldırma işlemi onay gerektirir. Harita katman adları Türkçeleştirildi; bu tam uygulama çevirisi değildir.

## Arka plan müziği

Kullanıcının yüklediği `public/videoplayback.mp3` doğrudan, %30 sesle ve döngüde oynatılır. Müzik sekmesi, dosya seçimi veya YouTube oynatıcısı yoktur. Sayfa açılırken otomatik oynatma denenir; tarayıcı izin vermezse ilk tıklama/dokunma veya tuş etkileşiminde yeniden denenir. Bu nedenle etkileşimsiz sesli başlangıç her tarayıcıda garanti edilmez. Sol alttaki küçük ses düğmesi müziği durdurur/başlatır. Kullanıcı düğmeyle durdurduğunda sonraki sayfa etkileşimleri müziği tekrar başlatmaz. Sayfa yenilendiğinde başlangıç yeniden denenir. Ses dosyası artık sitenin herkese açık statik içeriğidir.
