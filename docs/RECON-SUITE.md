# TUĞRUL RECON+ Suite

Açık kaynak OSINT platformlarının en olgun yöntemlerini TUĞRUL'a taşıyan yerinde (in-process) keşif katmanı. Ayrı bir tarayıcı servisi, API anahtarı veya harici kuyruk gerektirmez: her modül `src/lib/recon/` altında TypeScript olarak çalışır, sonuçlar `src/app/api/osint/*` rotalarından sunulur.

Arayüzde iki giriş vardır:

- **RECON paneli → RECON+ SUITE** düğmesi: dokuz modülün tamamı, tek bir masaüstü çalışma alanında.
- RECON panelinin kendi sekmeleri (SUBDOMAINS, HEADERS, TECH DETECT, SSL/TLS, VULN SWEEP): aynı motora `/api/scanner?type=…` üzerinden bağlanır. Daha önce `SCANNER_URL` tanımlı olmadığı için 503 dönen bu sekmeler artık çalışır.

## Nereden ne alındı

Seçim, GitHub'daki yıldız sayısı ve lisans netliğine göre yapıldı; ancak ölçüt yalnızca popülerlik değildi: **bakımı süren, lisansı ticari kullanıma uygun ve Türkiye odaklı bir platforma gizlilik riski getirmeyen** projeler alındı.

| Proje | Lisans | Ne alındı | Nerede görünür |
|---|---|---|---|
| [Sherlock](https://github.com/sherlock-project/sherlock) | MIT | 481 sitelik tespit veritabanı doğrudan tüketilir | USERNAME, FINGERPRINT |
| [Maigret](https://github.com/soxoj/maigret) | MIT | "Tek kimlik, tek dosya" rapor modeli | RECON+ DOSSIER |
| [subfinder](https://github.com/projectdiscovery/subfinder) | MIT | Pasif kaynak fan-out'u ve kaynak başına atıf | SUBDOMAINS |
| [theHarvester](https://github.com/laramies/theHarvester) | GPL-2.0 | Çok kaynaklı pasif host/e-posta/çalışan toplama yöntemi (kod alınmadı) | SUBDOMAINS, EMAIL |
| [Sublist3r](https://github.com/aboul3la/Sublist3r) | GPL-2.0 | Pasif kaynak + kelime listesi birleşimi | SUBDOMAINS (brute katmanı) |
| [Amass](https://github.com/owasp-amass/amass) | Apache-2.0 | İsim/adres/sertifikanın tek grafik olarak modellenmesi | grafik, dossier |
| [gau](https://github.com/lc/gau) | MIT | Wayback CDX'ten tarihsel URL toplama | URL HARVEST |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | MIT | Arşivi "sitenin eskiden neyi açığa çıkardığı"nın indeksi sayma | URL HARVEST |
| [Photon](https://github.com/s0md3v/Photon) | GPL-3.0 | URL'leri sızdırdıkları şeye göre sınıflandırma fikri | URL HARVEST bulguları |
| [pagodo](https://github.com/opsdisk/pagodo) | GPL-3.0 | Google dork kategorileri | DORKS |
| [OSINT Framework](https://github.com/lockfale/OSINT-Framework) | MIT | Analistin beklediği kategori ağacı | Araç Merkezi kaynak kütüphanesi |
| [webappanalyzer](https://github.com/enthec/webappanalyzer) | GPL-3.0 | Header/çerez/script yolundan yığın çıkarma yaklaşımı | TECH DETECT |
| [ExifTool](https://github.com/exiftool/exiftool) | Artistic-2.0 | Analistin aradığı etiket grupları | MEDIA META |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | MIT | "Tek tohum, bağımsız modüller, her modülün kendi durumu" modeli | RECON+ DOSSIER |
| [holehe](https://github.com/megadose/holehe) | GPL-3.0 | Yalnızca kavram; **etkin değil** | — |
| [GHunt](https://github.com/mxrch/GHunt) | AGPL-3.0 | Yalnızca kavram; **etkin değil** | — |

Lisansı GPL olan projelerden **kod kopyalanmadı**. Alınan şey yayımlanmış yöntemdir (hangi kaynağa ne sorulur, kanıt nasıl birleştirilir, hangi kural uygulanır); uygulama bağımsız TypeScript olarak yazıldı. MIT lisanslı veri dosyaları (Sherlock) doğrudan tüketilir ve atıf korunur.

### Bilerek dışarıda bırakılanlar

- **holehe / hesap varlığı yoklama:** Şifre sıfırlama akışlarıyla "bu hesap var mı" sorusu, sunucudan yapıldığında kimlik bilgisi doldurma (credential stuffing) trafiğinden ayırt edilemez. E-posta modülü bunun yerine yalnızca herkese açık kaynakları kullanır.
- **GHunt:** Google hesabı OSINT'i oturum çerezi ister. Platform kullanıcıdan oturum çerezi istemez.
- **nuclei / rengine / phoneinfoga:** Ağır tarayıcı altyapıları veya GPL kod tabanları. Yöntemleri (şablon tabanlı kontrol, varlık envanteri) kısmen izlenir; kod alınmadı.
- **Shodan/Censys/Dehashed gibi ücretli API'ler:** Anahtarsız çalışma ilkesi korunur. `.env.example` boş kalır.

## Modüller

| Modül | Dosya | Ne yapar |
|---|---|---|
| Ortak altyapı | `src/lib/recon/sources.ts` | Zaman aşımı, sınırlı eşzamanlılık, kaynak başına durum, host normalizasyonu, 16 entegrasyon kaydı |
| DNS + e-posta kayıtları | `dns.ts` | Google DoH üzerinden A/AAAA/MX/TXT/NS/CAA/PTR, SPF/DMARC/DKIM analizi |
| Dork üretici | `dorks.ts` | ~30 şablon, kategori ve risk, Google/Bing/DuckDuckGo/Yandex bağlantıları |
| Web parmak izi | `webtech.ts` | ~110 imza, güvenlik başlığı denetimi, çerez bayrakları, robots/security.txt, favicon MurmurHash3 (Shodan uyumlu) |
| TLS | `tls.ts` | Canlı el sıkışma, zincir, SAN, süre, zayıf protokol/şifre, A–F notu |
| Alt alan adları | `subdomains.ts` | crt.sh, Cert Spotter, OTX, HackerTarget, RapidDNS, Wayback, urlscan + isteğe bağlı 150 etiketlik DNS kaba kuvvet |
| URL hasadı | `urls.ts` | Wayback CDX, Common Crawl, OTX; 19 sınıflandırma kuralı |
| E-posta istihbaratı | `emailintel.ts` | Gravatar, XposedOrNot, emailrep, RDAP yaşı, SPF/DMARC/DKIM; ağırlıklı risk |
| Medya metaverisi | `exif.ts` | Tarayıcıda JPEG/PNG/TIFF/PDF etiketleri, GPS → ondalık + harita bağlantısı |
| CVE eşleme | `cve.ts` | ~45 ürün için CPE haritası, CIRCL araması, sürüm vs ürün eşleşmesi ayrımı |
| Grafik | `graph.ts` | Ad alanlı düğümler (`domain:`, `ip:`, `host:`, `technology:`…), tekilleştirilmiş kenarlar |
| Dossier | `dossier.ts` | Tohum tespiti, modül orkestrasyonu, risk rubriği, özet |

## API

| Rota | Parametreler | Sınır |
|---|---|---|
| `/api/osint/subdomains` | `domain`, `brute`, `quick`, `resolve`, `probe` | 6/dk |
| `/api/osint/webtech` | `url` | 20/dk |
| `/api/osint/tls` | `host`, `port` | 20/dk |
| `/api/osint/urls` | `domain`, `quick`, `limit` | 6/dk |
| `/api/osint/dorks` | `target`, `category`, `maxRisk` | 60/dk |
| `/api/osint/email` | `email`, `quick` | 10/dk |
| `/api/osint/vulns` | `url` **veya** `product` + `version` | 10/dk |
| `/api/osint/dossier` | `target`, `quick`, `brute` | 4/dk |
| `/api/scanner` | `target`, `type` | 20/dk |

Her rota özel/loopback hedefleri reddeder (`validateHost`). Ayrıntılı parametre ve dönüş açıklamaları uygulama içindeki **/docs** sayfasında (`apiCatalog.ts`) durur.

## Doğruluk sınırları

Bu modüller kanıt üretir, hüküm vermez:

- **Boş sonuç, olumsuz sonuç değildir.** Her kaynak kendi durumunu (`ok` / `empty` / `error`) bildirir. Düşen bir kaynak "böyle bir host yok" diye okunmamalıdır; arayüz bunu ayrı gösterir.
- **Pasif alt alan adı listeleri eksiktir.** Hiçbir yerde yayımlanmamış bir host hiçbir pasif kaynakta görünmez.
- **Arşiv URL'leri tarihseldir.** Bulunan yol yıllar önce kapanmış olabilir; bulgu "şu an açık" demek değildir.
- **Dork'lar taranmaz.** Üretilen sorgular tarayıcınızda açılır; arama motorunun koşulları size uygulanır.
- **EXIF dosyayı kanıtlamaz.** Etiketler değiştirilebilir. SHA-256 yalnızca içerik eşitliği içindir.
- **CVE eşleşmesi kesinlik taşımaz.** Sürüm eşleşmesi ürün eşleşmesinden güçlüdür; eşleşmeyen ürün "güvenli" demek değildir.
- **Risk puanı aritmetiktir.** Adlandırılmış bulguların ağırlıklı toplamıdır (100'de sınırlı; kritik ≥70, yüksek ≥45, orta ≥20) ve tartışmaya açıktır.
- **MEDIA META tarayıcıda çalışır.** Dosya hiçbir sunucuya gitmez; 25 MB sınırı vardır.

## Etik ve yetki

Platform yalnızca **yetkiniz olan sistemlerde** kullanılmak üzere tasarlandı. Kaba kuvvet katmanı (`brute=1`) ve HTTP yoklaması hedefe doğrudan trafik gönderir; izinsiz kullanım birçok ülkede suçtur. E-posta modülü hesap varlığı yoklamaz, oturum çerezi istemez ve kırılmış şifre aramaz.

## Testler

`src/lib/recon/*.test.ts` ve `src/app/api/osint/*/route.test.ts` altında ~200 birim testi vardır: MurmurHash3 vektörleri (Python `mmh3` referansıyla), elle kurulmuş TIFF/JPEG/PNG EXIF yapıları, yedi alt alan adı ayrıştırıcısı, URL sınıflandırıcısı, TLS not matrisi, CPE sürüm eşleşmesi, SSRF reddi ve hız sınırı döngüleri. Ağ erişimi `vi.stubGlobal('fetch', …)` ile taklit edilir; testler internet gerektirmez.
