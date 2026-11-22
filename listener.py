import http.server, socketserver, datetime
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(n)
        print('\n===== BEACON %s %s =====' % (datetime.datetime.now().strftime('%H:%M:%S'), self.path), flush=True)
        print(body.decode('utf-8', 'replace'), flush=True)
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(('0.0.0.0', 9090), H) as s:
    print('listening on 9090', flush=True); s.serve_forever()
