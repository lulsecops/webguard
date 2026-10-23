#!/usr/bin/env python3
"""WebGuard — Burak Şaşmaz / lulsecops. Standard-library HTTP configuration audit."""
import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

VERSION = '1.0.0'


def validate_url(value):
    if any(c.isspace() or ord(c) < 32 for c in value) or '\\' in value:
        raise ValueError('URL boşluk, kontrol karakteri veya ters eğik çizgi içeremez.')
    try:
        parts = urlsplit(value)
        port = parts.port
        if parts.scheme not in ('http', 'https') or not parts.hostname:
            raise ValueError('http:// veya https:// ile başlayan bir URL girin.')
        if parts.username is not None or parts.password is not None:
            raise ValueError('URL içinde kullanıcı adı veya parola kullanmayın.')
        if port is not None and not 1 <= port <= 65535:
            raise ValueError('Geçersiz port.')
        host = parts.hostname.encode('idna').decode('ascii')
        if ':' in host:
            host = '[' + host + ']'
        netloc = host + (':' + str(port) if port is not None else '')
        return urlunsplit((parts.scheme, netloc, parts.path or '/', parts.query, ''))
    except (UnicodeError, ValueError) as exc:
        raise ValueError(str(exc)) from exc


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url, timeout=10):
    # No body download, no automatic cross-host requests, normal TLS validation.
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(validate_url(url), method='HEAD', headers={'User-Agent': 'lulsecops-WebGuard/' + VERSION})
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc  # 3xx/4xx/5xx headers are still useful audit evidence.
    try:
        return response.status, response.headers
    finally:
        response.close()


def audit(url, status, headers):
    findings = []

    def add(code, level, message, advice):
        findings.append({'id': code, 'level': level, 'message': message, 'recommendation': advice})

    secure = urlsplit(url).scheme == 'https'
    if not secure:
        add('HTTPS', 'warning', 'İstek şifrelenmemiş HTTP üzerinden yapıldı.', 'HTTPS kullanın; varsa yönlendirme hedefini ayrıca değerlendirin.')
    hsts = headers.get('Strict-Transport-Security', '')
    age = re.search(r'(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)', hsts, re.I)
    if secure and (not age or int(age.group(1)) == 0):
        add('HSTS', 'warning', 'Etkin bir HSTS max-age değeri gözlenmedi.', 'HTTPS kapsamını doğruladıktan sonra uygun HSTS politikası tanımlayın.')
    csp = headers.get('Content-Security-Policy', '')
    if not csp.strip():
        add('CSP', 'review', 'Uygulanan Content-Security-Policy başlığı gözlenmedi.', 'HTML sayfalarında uygulamaya uygun CSP oluşturun; report-only politikası koruma uygulamaz.')
    directives = {item.strip().split()[0].lower(): item.strip().split()[1:] for item in csp.split(';') if item.strip()}
    xfo = headers.get('X-Frame-Options', '').strip().lower()
    if 'frame-ancestors' not in directives and xfo not in ('deny', 'sameorigin'):
        add('FRAMING', 'review', 'Çerçeveleme kısıtlaması gözlenmedi.', 'İhtiyaca göre CSP frame-ancestors veya X-Frame-Options kullanın.')
    if headers.get('X-Content-Type-Options', '').strip().lower() != 'nosniff':
        add('NOSNIFF', 'review', 'X-Content-Type-Options: nosniff gözlenmedi.', 'İçerikleri doğru MIME türüyle sunun ve nosniff başlığını ekleyin.')
    referrer = headers.get('Referrer-Policy', '')
    valid_policies = {'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url'}
    recognized = [p.strip().lower() for p in referrer.split(',') if p.strip().lower() in valid_policies]
    if not recognized:
        add('REFERRER', 'info', 'Açık bir geçerli Referrer-Policy gözlenmedi.', 'Tarayıcı varsayılanını ve uygulama ihtiyacını değerlendirin; strict-origin-when-cross-origin düşünülebilir.')
    elif recognized[-1] == 'unsafe-url':
        add('REFERRER', 'review', 'Referrer-Policy unsafe-url kullanıyor.', 'URL bilgilerinin başka sitelere gönderilmesini kısıtlayan bir politika değerlendirin.')
    if not headers.get('Permissions-Policy', '').strip():
        add('PERMISSIONS', 'info', 'Permissions-Policy gözlenmedi.', 'Gerekli olmayan kamera, mikrofon ve konum özelliklerini sınırlandırmayı değerlendirin.')
    if headers.get('Access-Control-Allow-Origin', '').strip() == '*':
        add('CORS', 'review', 'CORS tüm origin değerlerine açık.', 'Herkese açık kaynaklarda bu kasıtlı olabilir; hassas içerik için origin politikasını inceleyin.')
    cookies = headers.get_all('Set-Cookie', [])
    for index, cookie in enumerate(cookies, 1):
        # Never include cookie names or values in the exported report.
        attributes = [item.strip() for item in cookie.split(';')[1:]]
        keys = {item.split('=', 1)[0].lower() for item in attributes}
        same = [item.split('=', 1)[1].strip().lower() for item in attributes if '=' in item and item.split('=', 1)[0].lower() == 'samesite']
        missing = []
        if 'secure' not in keys:
            missing.append('Secure')
        if 'httponly' not in keys:
            missing.append('HttpOnly')
        if not same or same[-1] not in ('strict', 'lax', 'none'):
            missing.append('geçerli SameSite')
        if missing:
            add('COOKIE-' + str(index), 'review', 'Çerez #' + str(index) + ': ' + ', '.join(missing) + ' gözlenmedi.', 'Oturum çerezlerini değerlendirin; bazı istemci tarafı çerezleri HttpOnly gerektirmeyebilir.')
        if same and same[-1] == 'none' and 'secure' not in keys:
            add('COOKIE-NONE-' + str(index), 'warning', 'Çerez #' + str(index) + ': SameSite=None, Secure olmadan kullanılıyor.', 'SameSite=None için Secure kullanın; tarayıcılar çerezi reddedebilir.')
    location = headers.get('Location')
    redirect = None
    if 300 <= status < 400 and location:
        try:
            target = validate_url(urljoin(url, location))
            # Only report the origin and path; query strings may contain tokens.
            parts = urlsplit(target)
            redirect = urlunsplit((parts.scheme, parts.netloc, parts.path, '', ''))
            if secure and parts.scheme == 'http':
                add('DOWNGRADE', 'warning', 'Yönlendirme HTTPS üzerinden HTTP adresine gidiyor.', 'HTTPS hedefi kullanın.')
        except ValueError:
            add('REDIRECT', 'review', 'Yönlendirme hedefi desteklenen geçerli bir HTTP URL değil.', 'Location başlığını inceleyin.')
    if status in (405, 501):
        add('HEAD', 'info', 'Sunucu HEAD isteğini desteklemiyor.', 'Bu sonuç uygulamanın GET yanıtını temsil etmeyebilir; manuel doğrulayın.')
    parts = urlsplit(url)
    return {
        'tool': 'lulsecops WebGuard', 'author': 'Burak Şaşmaz', 'version': VERSION,
        'checked_at': datetime.now(timezone.utc).isoformat(),
        'target': urlunsplit((parts.scheme, parts.netloc, parts.path, '', '')),
        'status': status, 'redirect_target': redirect, 'cookie_count': len(cookies),
        'findings': findings,
        'limitations': 'Tek HEAD yanıtı incelendi; yönlendirmeler izlenmedi. Eksik başlıklar istismar kanıtı değildir. TLS doğrulaması bağlantı sırasında yapılır; TLS sürüm ve şifre takımı denetimi yapılmaz. Sorgu ve çerez değerleri rapora alınmaz; URL yolu hassas veri içerebilir.'
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description='Burak Şaşmaz / lulsecops WebGuard — Web güvenlik yapılandırması kontrolü')
    parser.add_argument('url', help='Kontrol etme yetkiniz olan http(s) URL')
    parser.add_argument('--json', dest='json_path', type=Path, help='JSON raporunu belirtilen yeni dosyaya kaydet')
    parser.add_argument('--timeout', type=float, default=10, help='Ağ zaman aşımı, saniye (varsayılan: 10)')
    parser.add_argument('--fail-on-warning', action='store_true', help='warning bulgusunda çıkış kodu 1 üret')
    args = parser.parse_args(argv)
    try:
        if not 0 < args.timeout <= 120:
            raise ValueError('Zaman aşımı 0 ile 120 saniye arasında olmalı.')
        url = validate_url(args.url)
        if args.json_path and args.json_path.exists():
            raise ValueError('Rapor dosyası zaten var; yeni bir dosya adı kullanın.')
        status, headers = fetch(url, args.timeout)
        result = audit(url, status, headers)
        if args.json_path:
            with args.json_path.open('x', encoding='utf-8') as report:
                json.dump(result, report, ensure_ascii=False, indent=2)
                report.write('\n')
    except (ValueError, OSError, urllib.error.URLError) as exc:
        # Avoid leaking URLs, proxy credentials, query tokens or server messages.
        if isinstance(exc, ValueError):
            message = str(exc)
        else:
            message = 'Bağlantı, TLS veya dosya işlemi başarısız (' + type(exc).__name__ + ').'
        print('Hata: ' + message, file=sys.stderr)
        return 2
    print('\nlulsecops WebGuard ' + VERSION + ' | Burak Şaşmaz')
    print('Hedef: ' + result['target'] + ' | HTTP ' + str(status))
    if result['redirect_target']:
        print('Yönlendirme (izlenmedi): ' + result['redirect_target'])
    for finding in result['findings']:
        print('\n[' + finding['level'].upper() + '] ' + finding['id'] + ': ' + finding['message'])
        print('  Öneri: ' + finding['recommendation'])
    if not result['findings']:
        print('İncelenen kurallarda bulgu yok. Bu sonuç güvenlik garantisi değildir.')
    print('\nSınırlar: ' + result['limitations'])
    if args.json_path:
        print('JSON raporu kaydedildi.')
    return int(args.fail_on_warning and any(f['level'] == 'warning' for f in result['findings']))


if __name__ == '__main__':
    sys.exit(main())
