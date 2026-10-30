# Yayınlama

## GitHub

Çalışma dalı: `arena/4089e7f8-tugrul-osint`.
İnceleme: https://github.com/keykavus324-svg/TUGRUL-OSINT/pull/1

## Vercel

Proje: `tugrul-osint`.

GitHub uygulama entegrasyonu bu Vercel hesabında kurulu olmadığı için ilk dağıtım bir **sabit commit arşivinden** kurulmuştur. Bu işlem GitHub parolası veya erişim anahtarı gerektirmez; depo herkese açıktır. Kaynak commit: `a405a1d`. Vercel kurulum komutu bu commit arşivini indirir, ardından `npm ci` çalıştırır. Derleme `npm run build` ile yapılır. Bootstrap manifesti Node.js 22 seçer.

**Otomatik dağıtım bağlı değildir.** Yeni değişikliklerin siteye geçmesi için Vercel GitHub uygulamasına bu depo erişimi verilerek proje Git'e bağlanmalı veya sabit commit adresi güncellenip yeniden dağıtılmalıdır. İlk dağıtımın arşiv komutu dalın son halini kendiliğinden takip etmez.

Üretim dağıtımında API anahtarları eklenmedi. Gerekli sağlayıcıları Vercel Environment Variables üzerinden yapılandırın. `.env` dosyalarını Git'e eklemeyin. Uzun süreli SSE bağlantıları ve bellek içi önbellekler sunucusuz platformun yaşam döngüsü sınırlarına tabidir; kapsamlı operasyonel kullanım için Docker/self-hosting değerlendirilmelidir.

## Kontroller

- Üretim derlemesi başarılı.
- 1513 test geçti, 27 canlı/isteğe bağlı test atlandı.
- Üretim bağımlılıkları: `npm audit --omit=dev --audit-level=high` sıfır bulgu.
- Sağlayıcı servislerinin tamamı uçtan uca doğrulanmadı; çalışması anahtarlar, erişim ve kota koşullarına bağlıdır.
