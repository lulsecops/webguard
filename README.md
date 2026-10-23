# lulsecops WebGuard

**Burak Şaşmaz · [sibersaldiri.com](https://www.sibersaldiri.com/)**

Python ile yazılmış, ek paket gerektirmeyen bir HTTP güvenlik yapılandırması kontrol aracı. Tek URL'ye bir HEAD isteği gönderir; sayfa gövdesini indirmez ve yönlendirmeleri izlemez. Güvenlik başlıkları ve çerez ayarlarına ilişkin Türkçe bulgular ve öneriler üretir. Bu bir istismar veya kapsamlı zafiyet tarama aracı değildir.

## Başlangıç

Python 3.10 veya üzeri gerekir.

```console
python webguard.py https://www.sibersaldiri.com/
python webguard.py https://example.com/ --json rapor.json
python webguard.py https://example.com/ --timeout 15 --fail-on-warning
```

Yalnızca kontrol etme yetkiniz olan hedeflerde kullanın. Proxy ortam ayarları Python tarafından dikkate alınır. TLS sertifikası doğrulaması açık kalır.

## Kontroller

| Kontrol | Değerlendirme |
| --- | --- |
| HTTPS | Şifrelenmemiş istekler ve HTTPS → HTTP yönlendirmeleri |
| HSTS | HTTPS yanıtında pozitif max-age varlığı |
| CSP | Uygulanan politikanın varlığı; tam politika analizi yapılmaz |
| Çerçeveleme | frame-ancestors veya geçerli X-Frame-Options varlığı |
| MIME | X-Content-Type-Options: nosniff |
| Referrer | Geçerli açık politika ve unsafe-url kullanımı |
| İzinler | Permissions-Policy varlığı |
| CORS | Wildcard origin kullanımı için manuel inceleme notu |
| Çerezler | Secure, HttpOnly ve SameSite; her Set-Cookie ayrı değerlendirilir |

`warning`: önemli yapılandırma sinyali; `review`: bağlama göre inceleme; `info`: bilgi. Eksik başlıklar tek başına sömürülebilir açık anlamına gelmez. Yönlendirme ve HEAD yanıtları nihai HTML yanıtından farklı olabilir. Tarayıcının varsayılan politikaları ve HTML meta etiketleri değerlendirilmez. Tam TLS protokolü, sertifika envanteri veya şifre takımı analizi yapılmaz.

Raporlara çerez değerleri, yanıt başlıklarının tamamı veya URL sorguları eklenmez. **URL yolu hassas veri içerebilir; paylaşmadan önce raporu inceleyin.** Var olan rapor dosyasının üzerine yazılmaz.

Çıkış kodları: `0` tamamlandı; `1` yalnızca --fail-on-warning ile warning bulundu; `2` bağlantı/girdi/dosya hatası.

## Doğrulama

```console
python -m unittest discover -s tests -v
```

Testler yerel sunucu kullanır; dış hedef taramaz.

## Yazar

Burak Şaşmaz / **lulsecops** · Siber Güvenlik & Pentest

[GitHub](https://github.com/lulsecops) · [Web sitesi](https://www.sibersaldiri.com/) · [İletişim](https://www.sibersaldiri.com/iletisim)
