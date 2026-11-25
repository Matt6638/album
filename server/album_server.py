#!/usr/bin/env python3
"""フォトアルバム用の小さなサーバー（Python 標準ライブラリだけで動作）

外付けHDDなどのフォルダを、iPhone などのブラウザからアルバム形式で見るためのもの。
- 127.0.0.1 だけで待ち受ける（外からは Tailscale の serve 経由でのみ届く想定）
- 読み取り専用：ファイルの作成・変更・削除は一切しない
- サムネイルは macOS 標準の sips / qlmanage で作り、キャッシュフォルダに保存する

使い方:
  python3 album_server.py --root "/Volumes/Family_ハードディスク" --app ./app --port 8787
"""
import argparse, hashlib, json, mimetypes, os, re, shutil, subprocess, sys, tempfile, threading, urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

IMG_EXT = {'jpg', 'jpeg', 'jpe', 'png', 'gif', 'webp', 'bmp', 'avif', 'heic', 'heif'}
VID_EXT = {'mp4', 'mov', 'm4v', 'webm', 'mkv', '3gp'}
SKIP_DIRS = {'$RECYCLE.BIN', 'System Volume Information'}
EXTRA_TYPES = {'.heic': 'image/heic', '.heif': 'image/heif', '.mov': 'video/quicktime', '.m4v': 'video/x-m4v',
               '.mp4': 'video/mp4', '.webmanifest': 'application/manifest+json', '.js': 'text/javascript',
               '.svg': 'image/svg+xml', '.mkv': 'video/x-matroska', '.3gp': 'video/3gpp'}
CHUNK = 256 * 1024
THUMB = 480
thumb_sem = threading.Semaphore(3)

def ext_of(name):
    i = name.rfind('.')
    return name[i + 1:].lower() if i >= 0 else ''

def kind_of(name):
    if name.startswith('.'):
        return None
    e = ext_of(name)
    return 'image' if e in IMG_EXT else 'video' if e in VID_EXT else None

def ctype(path):
    e = os.path.splitext(path)[1].lower()
    return EXTRA_TYPES.get(e) or mimetypes.guess_type(path)[0] or 'application/octet-stream'

class Handler(BaseHTTPRequestHandler):
    server_version = 'AlbumServer/1'
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):  # 通常のアクセスログは出さない（ファイル名を残さないため）
        pass

    # ---- 共通 ----
    def send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def send_err(self, code, msg=''):
        body = msg.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def safe_path(self, rel, base):
        """base の中にあるパスだけを許可する（.. や隠しファイル、シンボリックリンクでの抜け出しを防ぐ）"""
        parts = [p for p in rel.split('/') if p not in ('', '.')]
        if any(p == '..' or p.startswith('.') for p in parts):
            return None
        full = os.path.realpath(os.path.join(base, *parts))
        real_base = os.path.realpath(base)
        if full != real_base and not full.startswith(real_base + os.sep):
            return None
        return full

    def do_HEAD(self):
        self.do_GET(head=True)

    def do_GET(self, head=False):
        u = urllib.parse.urlsplit(self.path)
        path = urllib.parse.unquote(u.path)
        q = urllib.parse.parse_qs(u.query)
        try:
            if path == '/api/info':
                root = self.server.root
                return self.send_json({'app': 'photo-album-server', 'version': 1, 'name': os.path.basename(root.rstrip('/')),
                                       'available': os.path.isdir(root)})
            if path == '/api/list':
                return self.api_list(q.get('path', [''])[0])
            if path.startswith('/media/'):
                return self.send_file(self.safe_path(path[len('/media/'):], self.server.root), head, media=True)
            if path.startswith('/thumb/'):
                return self.send_thumb(self.safe_path(path[len('/thumb/'):], self.server.root), head)
            rel = path.lstrip('/') or 'index.html'
            if rel.endswith('/'):
                rel += 'index.html'
            return self.send_file(self.safe_path(rel, self.server.app), head, media=False)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # ---- フォルダ一覧 ----
    def api_list(self, rel):
        root = self.server.root
        if not os.path.isdir(root):
            return self.send_json({'error': 'HDDが見つかりません（接続されているか確認してください）'}, 503)
        full = self.safe_path(rel, root)
        if not full or not os.path.isdir(full):
            return self.send_json({'error': 'フォルダが見つかりません'}, 404)
        dirs, files = [], []
        try:
            with os.scandir(full) as it:
                for e in it:
                    if e.name.startswith('.'):
                        continue
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if e.name not in SKIP_DIRS:
                                dirs.append(e.name)
                        elif e.is_file(follow_symlinks=False) and kind_of(e.name):
                            st = e.stat()
                            files.append({'name': e.name, 'size': st.st_size, 'mtime': int(st.st_mtime * 1000)})
                    except OSError:
                        continue
        except PermissionError:
            return self.send_json({'error': 'このフォルダは開けません（アクセス権がありません）'}, 403)
        self.send_json({'dirs': dirs, 'files': files})

    # ---- ファイル送信（動画の途中再生に必要な Range 要求に対応） ----
    def send_file(self, full, head, media):
        if not full or not os.path.isfile(full) or (media and not kind_of(os.path.basename(full))):
            return self.send_err(404, 'not found')
        size = os.path.getsize(full)
        start, end = 0, size - 1
        rng = self.headers.get('Range')
        status = 200
        if rng:
            m = re.match(r'bytes=(\d*)-(\d*)$', rng.strip())
            if not m or (m.group(1) == '' and m.group(2) == ''):
                self.send_response(416); self.send_header('Content-Range', f'bytes */{size}'); self.send_header('Content-Length', '0'); self.end_headers(); return
            if m.group(1) == '':
                n = int(m.group(2)); start = max(0, size - n)
            else:
                start = int(m.group(1))
                if m.group(2):
                    end = min(int(m.group(2)), size - 1)
            if start > end or start >= size:
                self.send_response(416); self.send_header('Content-Range', f'bytes */{size}'); self.send_header('Content-Length', '0'); self.end_headers(); return
            status = 206
        length = end - start + 1
        self.send_response(status)
        self.send_header('Content-Type', ctype(full))
        self.send_header('Accept-Ranges', 'bytes')
        self.send_header('Content-Length', str(length))
        if status == 206:
            self.send_header('Content-Range', f'bytes {start}-{end}/{size}')
        self.send_header('Cache-Control', 'private, max-age=3600' if media else 'no-cache')
        self.end_headers()
        if head:
            return
        with open(full, 'rb') as f:
            f.seek(start)
            left = length
            while left > 0:
                buf = f.read(min(CHUNK, left))
                if not buf:
                    break
                self.wfile.write(buf)
                left -= len(buf)

    # ---- サムネイル ----
    def send_thumb(self, full, head):
        if not full or not os.path.isfile(full):
            return self.send_err(404, 'not found')
        k = kind_of(os.path.basename(full))
        if not k:
            return self.send_err(404, 'not found')
        st = os.stat(full)
        key = hashlib.sha1(f'{full}|{st.st_size}|{st.st_mtime}'.encode('utf-8')).hexdigest()
        cache = os.path.join(self.server.cache, key[:2], key + '.jpg')
        if not os.path.exists(cache):
            with thumb_sem:
                if not os.path.exists(cache):
                    ok = make_thumb(full, k, cache)
                    if not ok:
                        return self.send_err(404, 'thumbnail failed')
        with open(cache, 'rb') as f:
            data = f.read()
        self.send_response(200)
        self.send_header('Content-Type', 'image/jpeg')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'private, max-age=31536000, immutable')
        self.end_headers()
        if not head:
            self.wfile.write(data)

def make_thumb(src, kind, out):
    """macOS の sips（画像）/ qlmanage（動画）でサムネイルを作る。どちらも元ファイルは変更しない"""
    os.makedirs(os.path.dirname(out), exist_ok=True)
    tmpdir = tempfile.mkdtemp(prefix='albumthumb-')
    try:
        if kind == 'image' and shutil.which('sips'):
            tmp = os.path.join(tmpdir, 't.jpg')
            r = subprocess.run(['sips', '-s', 'format', 'jpeg', '-s', 'formatOptions', '80', '-Z', str(THUMB), src, '--out', tmp],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
            if r.returncode == 0 and os.path.exists(tmp):
                shutil.move(tmp, out); return True
        if kind == 'video' and shutil.which('qlmanage'):
            subprocess.run(['qlmanage', '-t', '-s', str(THUMB), '-o', tmpdir, src],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90)
            pngs = [f for f in os.listdir(tmpdir) if f.endswith('.png')]
            if pngs:
                png = os.path.join(tmpdir, pngs[0]); tmp = os.path.join(tmpdir, 't.jpg')
                r = subprocess.run(['sips', '-s', 'format', 'jpeg', '-s', 'formatOptions', '80', png, '--out', tmp],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
                if r.returncode == 0 and os.path.exists(tmp):
                    shutil.move(tmp, out); return True
        # macOS 以外（テスト用）：画像は元ファイルをそのまま使う
        if kind == 'image' and not shutil.which('sips') and ext_of(src) in ('jpg', 'jpeg', 'png'):
            shutil.copyfile(src, out); return True
        return False
    except (subprocess.TimeoutExpired, OSError):
        return False
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True, help='アルバムとして見せるフォルダ（外付けHDDなど）')
    ap.add_argument('--app', required=True, help='アプリ（index.html など）のフォルダ')
    ap.add_argument('--port', type=int, default=8787)
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--cache', default=os.path.expanduser('~/Library/Caches/AlbumServer'))
    a = ap.parse_args()
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    srv.daemon_threads = True
    srv.root = os.path.abspath(a.root)
    srv.app = os.path.abspath(a.app)
    srv.cache = a.cache
    os.makedirs(srv.cache, exist_ok=True)
    print(f'AlbumServer: http://{a.host}:{a.port}/  root={srv.root}', flush=True)
    srv.serve_forever()

if __name__ == '__main__':
    main()
