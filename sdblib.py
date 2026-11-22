import re, socket, struct, time
class Sdb:
    def __init__(self, ip):
        self.sock = socket.create_connection((ip, 26101), timeout=15)
        self.buf = b''; self.next_id = 1
        self.okay, self.inbox, self.closed = {}, {}, set()
        self.send(b'CNXN', 0x01000000, 4096, b'host::\0')
        cmd, _, max_data, data = self.read()
        if cmd != b'CNXN': raise ConnectionError('answered %r' % cmd)
        self.max = min(max_data, 4096); self.banner = data.rstrip(b'\0').decode('utf-8','replace')
    def send(self, cmd, arg0, arg1, data=b''):
        c = struct.unpack('<I', cmd)[0]
        self.sock.sendall(struct.pack('<6I', c, arg0, arg1, len(data), sum(data) & 0xFFFFFFFF, c ^ 0xFFFFFFFF) + data)
    def _recv(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk: raise ConnectionError('closed')
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]; return out
    def read(self):
        cmd, arg0, arg1, n, _, _ = struct.unpack('<6I', self._recv(24))
        return struct.pack('<I', cmd), arg0, arg1, self._recv(n) if n else b''
    def pump(self):
        cmd, remote, local, data = self.read()
        if cmd == b'OKAY': self.okay[local] = remote
        elif cmd == b'WRTE':
            self.inbox[local] = self.inbox.get(local, b'') + data; self.send(b'OKAY', local, remote)
        elif cmd == b'CLSE': self.closed.add(local)
    def open(self, service):
        local, self.next_id = self.next_id, self.next_id + 1
        self.send(b'OPEN', local, 0, service.encode() + b'\0')
        while local not in self.okay:
            if local in self.closed: raise ConnectionError('refused ' + service)
            self.pump()
        return local, self.okay.pop(local)
    def write(self, stream, data):
        local, remote = stream
        self.send(b'WRTE', local, remote, data)
        while local not in self.okay:
            if local in self.closed: raise ConnectionError('stream closed')
            self.pump()
        del self.okay[local]
    def read_until(self, stream, done, seconds):
        local = stream[0]; end = time.time() + seconds
        while time.time() < end and local not in self.closed and not done(self.inbox.get(local, b'')):
            self.sock.settimeout(max(0.1, end - time.time()))
            try: self.pump()
            except socket.timeout: break
        self.sock.settimeout(15)
        return self.inbox.pop(local, b'')
    def shell(self, command, until=None, seconds=20):
        stream = self.open('shell:' + command)
        out = self.read_until(stream, lambda t: bool(until and re.search(until, t.decode('utf-8','replace'))), seconds)
        return out.decode('utf-8','replace')
    def capabilities(self):
        text = self.read_until(self.open('capability:'), lambda t: False, 5).decode('utf-8','replace')
        return dict(l.split(':',1) for l in text.splitlines() if ':' in l)
    def push(self, path, data):
        stream = self.open('sync:')
        spec = ('%s,%d' % (path, 0o100644)).encode()
        self.write(stream, b'SEND' + struct.pack('<I', len(spec)) + spec)
        step = self.max - 8
        for i in range(0, len(data), step):
            part = data[i:i+step]
            self.write(stream, b'DATA' + struct.pack('<I', len(part)) + part)
        self.write(stream, b'DONE' + struct.pack('<I', int(time.time())))
        answer = self.read_until(stream, lambda t: len(t) >= 8, 60)
        if answer[:4] != b'OKAY': raise ConnectionError('push failed: ' + answer[8:].decode('utf-8','replace'))
        self.send(b'WRTE', stream[0], stream[1], b'QUIT' + struct.pack('<I', 0))

