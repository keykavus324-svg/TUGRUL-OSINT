# TUĞRUL Analyst Suite

## Kullanım

Sağ üstteki kutucuklar ikonuna basın. Araçlar tek bir isteğe bağlı paneldedir; harita ilk açılışta geniş kalır. Masaüstünde araç araması, mobilde yatay araç gezinmesi vardır. Escape paneli kapatır ve odağı açma düğmesine geri verir. Klavye odağı açık panelde tutulur.

## Veri ve mahremiyet

- `tugrul.toolkit.v1` localStorage anahtarı izleme listesi ve zaman çizelgesini saklar. **Şifrelenmez.** Aynı tarayıcı profiline erişen biri kayıtları okuyabilir. Özel, gizli veya hassas bilgi eklemeyin.
- Araştırma Merkezi'nin eski `tugrul.research.v1` bulguları ayrı kalır; yeni yedek bu bulguları içermez.
- Dosya parmak izi, gösterge çıkarma, koordinat hesapları ve URL temizleme yerel çalışır; girdiler bir sunucuya yüklenmez.
- DNS yalnızca **DNS sorgula** düğmesinde çalışır. Alan adı Google Public DNS'ye gider. İstek için 12 saniyelik zaman aşımı ve eski sorgu sonuçlarına karşı iptal vardır. Sayfa açılışında DNS isteği yapılmaz.
- Dış arama/kaynak bağlantıları ilgili sorguyu sağlayıcıya gönderir ve yeni sekmede açılır. Sağlayıcı koşulları geçerlidir. DNS dışındaki ağ inceleme bağlantıları gömülü entegrasyon değildir.
- İzleme listesi **manuel**dir: arka planda tarama, bildirim, periyodik kontrol veya hedef hakkında otomatik çıkarım yapmaz.
- Doğrulama listesi ve zaman dönüşümü oturumluk, diğer araç girdileri uygulama bileşeni açık kaldığı sürece bellektedir. Saklandığı belirtilmeyen formlar sayfa yenilemede kaybolur.

## İçe/dışa aktarma

JSON yedek biçimi `schema: tugrul.toolkit.v1`, `exportedAt`, `data.watch` ve `data.timeline` içerir. En fazla 1 MB metin, 200 hedef, 300 olay. Tüm kayıtlar saklanmadan önce doğrulanır: kimlik, UTC zaman damgası, uzunluk, tür, alan adı/IPv4 ve HTTP(S) kaynak adresi. Aynı kimlikli kayıtlar birleştirmede tekrar eklenmez. Limit aşılırsa tüm işlem reddedilir; eski dosya korunur. Tarayıcı depolaması kullanılamıyorsa hata gösterilir; başarılıymış gibi davranılmaz.

Kaynak dağılımı yalnızca analistin girdiği olayların kaynak alan adlarını sayar. Ortak alan adı; sahiplik, koordinasyon veya olay bağlantısı kanıtı değildir. Markdown raporu analist kaydıdır; resmi delil veya otomatik teyit belgesi değildir.

## Doğruluk sınırları

- Sismik tarayıcı ana uygulamanın yüklediği kayıtlarla sınırlıdır. Boş sonuç, gerçek dünyada olay olmadığı anlamına gelmez.
- Mesafe 6371 km yarıçaplı küre üzerinde büyük daire yaklaşımıdır. Yol veya arazi rotası değildir. Aynı noktalarda ilk yön açısı gösterilmez.
- SHA-256 içerik eşitliği karşılaştırması içindir. Dosyanın güvenliğini/gerçekliğini veya ilk oluşturulma zamanını ispatlamaz. Dosya limiti 20 MB.
- Metin çıkarımı desen eşleştirmedir; bulunan ifade tehdit veya kimlik doğrulaması değildir. Metin 100.000 karakter, her çıktı türü en fazla 200 kayıttır. IPv4 desteklenir, IPv6 çıkarımı yoktur.
- URL temizleme güvenlik taraması değildir; imzalı linkleri bozabilir.
- Kontrol listesinde bütün kutuların işaretlenmesi bile bir iddiayı doğrulanmış yapmaz. Teyit durumu açıkça analist değerlendirmesidir.

## Kontroller

54 yardımcı fonksiyon testi ve kapalı varsayılan panel testi. Chromium'da arama üretimi, DNS isteğinin sadece tıklamada başlaması (test yanıtı), gösterge/URL/koordinat işlemleri, bilinen `abc` dosyası için SHA-256, kayıtların yenilemede korunması, rapor indirme, geçersiz yedek reddi, saat dönüşümü ve klavye odağı denetlendi. 1440 px masaüstü ve 390 px mobil ekranlarda taşma/sayfa hatası görülmedi. Canlı DNS ve tüm dış kaynakların erişilebilirliği geliştirme ağından uçtan uca doğrulanmadı.
