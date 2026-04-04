#!/usr/bin/env python3
"""Minimal HTTP server on localhost:8080."""
from http.server import HTTPServer, BaseHTTPRequestHandler

HTML = b"""<!DOCTYPE html>
<html>
<head><title>hyperdht-cpp</title></head>
<body style="font-family:monospace;max-width:600px;margin:80px auto;text-align:center">
<h1>It works!</h1>
<p>This page is served over a P2P tunnel powered by
<strong>libhyperdht</strong> (C++) + Python.</p>
<p>The connection is end-to-end encrypted (Noise IK + SecretStream)
and traversed your NAT via holepunching.</p>
<p><code>holesail-py + hyperdht-cpp</code></p>
</body>
</html>
"""

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(HTML)
    def log_message(self, *a):
        pass

HTTPServer(("127.0.0.1", 8080), H).serve_forever()
