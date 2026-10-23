import importlib.util
import json
import tempfile
import threading
import unittest
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

spec = importlib.util.spec_from_file_location('webguard', Path(__file__).resolve().parents[1] / 'webguard.py')
wg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wg)


class AuditTests(unittest.TestCase):
    def test_duplicate_cookies_and_redaction(self):
        headers = Message()
        headers.add_header('Set-Cookie', 'secret=TOPSECRET; SameSite=None')
        headers.add_header('Set-Cookie', 'session=SECONDSECRET; Secure; HttpOnly; SameSite=Lax')
        result = wg.audit('https://example.com/?token=PRIVATE', 200, headers)
        text = json.dumps(result)
        for secret in ['TOPSECRET', 'SECONDSECRET', 'PRIVATE']:
            self.assertNotIn(secret, text)
        self.assertEqual(result['cookie_count'], 2)
        self.assertIn('COOKIE-NONE-1', [f['id'] for f in result['findings']])
        self.assertNotIn('COOKIE-2', [f['id'] for f in result['findings']])

    def test_protected_response(self):
        headers = Message()
        for name, value in {'Strict-Transport-Security': 'max-age=31536000', 'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'", 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'strict-origin-when-cross-origin', 'Permissions-Policy': 'camera=()'}.items():
            headers[name] = value
        self.assertEqual(wg.audit('https://example.com/', 200, headers)['findings'], [])

    def test_invalid_urls(self):
        for url in ['file:///etc/passwd', 'https://user:secret@example.com/', 'https://example.com:99999', 'https://example.com/\nInjected', '//example.com']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                wg.validate_url(url)

    def test_redirect_not_followed_and_error_headers(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                requests.append(self.path)
                self.send_response(302 if self.path == '/' else 405)
                self.send_header('Location', '/private?token=HIDDEN')
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = 'http://127.0.0.1:' + str(server.server_port) + '/'
            status, headers = wg.fetch(url)
            self.assertEqual(status, 302)
            self.assertEqual(requests, ['/'])
            self.assertNotIn('HIDDEN', json.dumps(wg.audit(url, status, headers)))
            status, headers = wg.fetch(url + 'unsupported')
            self.assertEqual(status, 405)
            self.assertIn('HEAD', [f['id'] for f in wg.audit(url, status, headers)['findings']])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main()
