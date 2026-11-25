#!/usr/bin/env python3
"""フォトアルバム用の小さなサーバー（Python 標準ライブラリだけで動作）

外付けHDDなどのフォルダを、iPhone などのブラウザからアルバム形式で見るためのもの。
- 127.0.0.1 だけで待ち受ける（外からは Tailscale の serve 経由でのみ届く想定）
- 写真・動画の追加（アップロード）、フォルダの作成、移動、名前の変更ができる。上書きはしない
  （同じ名前があれば「名前 (2).jpg」のように別名にする）
- 削除はすぐには消さず、HDDの「.album-trash」（ゴミ箱）に移す。アプリのゴミ箱から元に戻せる
- サムネイルは macOS 標準の sips / qlmanage で作り、キャッシュフォルダに保存する

使い方:
  python3 album_server.py --root "/Volumes/Family_ハードディスク" --app ./app --port 8787
"""
import argparse, hashlib, hmac, json, mimetypes, os, re, secrets, shutil, subprocess, sys, tempfile, threading, time, unicodedata, urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

IMG_EXT = {'jpg', 'jpeg', 'jpe', 'png', 'gif', 'webp', 'bmp', 'avif', 'heic', 'heif'}
VID_EXT = {'mp4', 'mov', 'm4v', 'webm', 'mkv', '3gp'}
SKIP_DIRS = {'$RECYCLE.BIN', 'System Volume Information'}
EXTRA_TYPES = {'.heic': 'image/heic', '.heif': 'image/heif', '.mov': 'video/quicktime', '.m4v': 'video/x-m4v',
               '.mp4': 'video/mp4', '.webmanifest': 'application/manifest+json', '.js': 'text/javascript',
               '.svg': 'image/svg+xml', '.mkv': 'video/x-matroska', '.3gp': 'video/3gpp'}
CHUNK = 256 * 1024
PW_ITER = 300000
SESSION_DAYS = 180
LOCK_FAILS, LOCK_SECONDS = 5, 15 * 60
COOKIE = 'albsess'
FREE_MARGIN = 1024 ** 3          # 追加後もHDDに最低1GBは空きを残す
MAX_UPLOAD = 64 * 1024 ** 3      # 1ファイルの上限（64GB）
NAME_LOCK = threading.Lock()
TRASH = '.album-trash'           # ゴミ箱（HDDのいちばん上の隠しフォルダ）     # 保存名の決定と確定を同時に行わないための鍵

def clean_name(n):
    """保存するファイル名・フォルダ名を安全な形にする。使えない名前なら空文字"""
    n = unicodedata.normalize('NFC', str(n)).strip()
    n = re.sub(r'[\x00-\x1f/\\:]', '_', n)
    if not n or n.startswith('.') or len(n.encode('utf-8')) > 240:
        return ''
    return n

def pw_hash(pw, salt=None, it=PW_ITER):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), bytes.fromhex(salt), it).hex()
    return {'salt': salt, 'hash': h, 'iter': it}

def pw_check(pw, rec):
    if not rec:
        return False
    h = hashlib.pbkdf2_hmac('sha256', pw.encode('utf-8'), bytes.fromhex(rec['salt']), rec['iter']).hex()
    return hmac.compare_digest(h, rec['hash'])

class Auth:
    """家族ごとのログイン。users.json（人ごとの見られるフォルダ・パスワードのハッシュ・招待コードのハッシュ）を使う"""
    def __init__(self, path):
        self.path = path
        self.sess_path = os.path.join(os.path.dirname(path), 'sessions.json')
        self.lock = threading.Lock()
        self.fails = {}   # user -> [回数, 最初の失敗時刻]
        self.data = json.load(open(path, encoding='utf-8'))
        try:
            self.sessions = json.load(open(self.sess_path, encoding='utf-8'))
        except (OSError, ValueError):
            self.sessions = {}

    def _save(self):
        for path, obj in ((self.path, self.data), (self.sess_path, self.sessions)):
            tmp = path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(obj, f, ensure_ascii=False, indent=1)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)

    def users_public(self):
        return [{'id': k, 'name': u['display'], 'ready': bool(u.get('pw'))} for k, u in self.data['users'].items()]

    def user_of(self, token):
        if not token:
            return None
        th = hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            s = self.sessions.get(th)
            if not s or s['exp'] < time.time() or s['user'] not in self.data['users']:
                return None
            return s['user']

    def folders(self, uid):
        return list(self.data['users'][uid].get('folders', []))

    def _locked(self, uid):
        f = self.fails.get(uid)
        return bool(f and f[0] >= LOCK_FAILS and time.time() - f[1] < LOCK_SECONDS)

    def _fail(self, uid):
        f = self.fails.get(uid)
        if not f or time.time() - f[1] >= LOCK_SECONDS:
            f = [0, time.time()]
        f[0] += 1
        self.fails[uid] = f

    def _new_session(self, uid):
        token = secrets.token_urlsafe(32)
        now = time.time()
        self.sessions = {k: v for k, v in self.sessions.items() if v['exp'] > now}
        self.sessions[hashlib.sha256(token.encode()).hexdigest()] = {'user': uid, 'exp': now + SESSION_DAYS * 86400}
        self._save()
        return token

    def login(self, uid, pw):
        with self.lock:
            u = self.data['users'].get(uid)
            if not u:
                return None, '名前が見つかりません'
            if self._locked(uid):
                return None, '続けて間違えたため、15分ほど待ってからやり直してください'
            if not u.get('pw'):
                return None, 'まだパスワードが設定されていません（「はじめて使う」から設定してください）'
            if not pw_check(pw, u['pw']):
                self._fail(uid)
                return None, 'パスワードが違います'
            self.fails.pop(uid, None)
            return self._new_session(uid), ''

    def setup(self, uid, invite, pw):
        with self.lock:
            u = self.data['users'].get(uid)
            if not u:
                return None, '名前が見つかりません'
            if u.get('pw'):
                return None, 'この名前はパスワード設定済みです。ログインしてください'
            if self._locked(uid):
                return None, '続けて間違えたため、15分ほど待ってからやり直してください'
            if len(pw) < 8:
                return None, 'パスワードは8文字以上にしてください'
            code = re.sub(r'[\s-]', '', invite or '').upper()
            if not pw_check(code, u.get('invite')):
                self._fail(uid)
                return None, '招待コードが違います'
            u['pw'] = pw_hash(pw)
            u.pop('invite', None)
            self.fails.pop(uid, None)
            return self._new_session(uid), ''

    def logout(self, token):
        with self.lock:
            if token:
                self.sessions.pop(hashlib.sha256(token.encode()).hexdigest(), None)
                self._save()
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

    def token(self):
        for part in (self.headers.get('Cookie') or '').split(';'):
            k, _, v = part.strip().partition('=')
            if k == COOKIE:
                return v
        return ''

    def current_user(self):
        a = self.server.auth
        return a.user_of(self.token()) if a else None

    def allowed(self, rel):
        """ログイン中の人がこのパスを見てよいか（先頭のフォルダで判定）。ログイン機能なしなら常に許可"""
        a = self.server.auth
        if not a:
            return True
        uid = self.current_user()
        if not uid:
            return False
        top = [p for p in rel.split('/') if p][:1]
        return (not top) or top[0] in a.folders(uid)

    def secure_cookie(self):
        host = (self.headers.get('Host') or '').split(':')[0]
        return host.endswith('.ts.net') or self.headers.get('X-Forwarded-Proto') == 'https'

    def set_cookie(self, token, max_age):
        c = f'{COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}'
        if self.secure_cookie():
            c += '; Secure'
        self.send_header('Set-Cookie', c)

    def read_json(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n <= 0 or n > 2000000:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode('utf-8'))
        except ValueError:
            return {}

    def same_origin(self):
        """ほかのサイトからの書き込み要求を断る"""
        o = self.headers.get('Origin')
        if not o:
            return True
        return urllib.parse.urlsplit(o).netloc == (self.headers.get('Host') or '')

    def do_POST(self):
        a = self.server.auth
        u = urllib.parse.urlsplit(self.path)
        path = u.path
        if not self.same_origin():
            self.close_connection = True
            return self.send_json({'error': 'このページからは操作できません'}, 403)
        try:
            if path == '/api/upload':
                return self.api_upload(urllib.parse.parse_qs(u.query))
            if path == '/api/mkdir':
                return self.api_mkdir(self.read_json())
            if path == '/api/trash':
                return self.api_trash(self.read_json())
            if path == '/api/trash/restore':
                return self.api_trash_act(self.read_json(), restore=True)
            if path == '/api/trash/purge':
                return self.api_trash_act(self.read_json(), restore=False)
            if path == '/api/move':
                return self.api_move(self.read_json())
            if path == '/api/rename':
                return self.api_rename(self.read_json())
        except (BrokenPipeError, ConnectionResetError):
            return
        if not a or path not in ('/api/login', '/api/setup', '/api/logout'):
            self.close_connection = True
            return self.send_err(404, 'not found')
        body = self.read_json()
        if path == '/api/logout':
            a.logout(self.token())
            body = b'{"ok": true}'
            self.send_response(200); self.set_cookie('', 0)
            self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(body))); self.end_headers()
            self.wfile.write(body); return
        uid = str(body.get('user', ''))
        if path == '/api/login':
            token, err = a.login(uid, str(body.get('password', '')))
        else:
            token, err = a.setup(uid, str(body.get('invite', '')), str(body.get('password', '')))
        if not token:
            return self.send_json({'error': err}, 403)
        out = json.dumps({'ok': True, 'me': {'id': uid, 'name': a.data['users'][uid]['display']}}, ensure_ascii=False).encode('utf-8')
        self.send_response(200); self.set_cookie(token, 180 * 86400)
        self.send_header('Content-Type', 'application/json; charset=utf-8'); self.send_header('Content-Length', str(len(out)))
        self.send_header('Cache-Control', 'no-store'); self.end_headers()
        self.wfile.write(out)

    def write_dir(self, rel):
        """書き込んでよいフォルダの実パスを返す。だめなら (None, (status, message))"""
        a = self.server.auth
        if a and not self.current_user():
            return None, (401, 'ログインしてください')
        parts = [p for p in rel.split('/') if p]
        if a and (not parts or not self.allowed(rel)):
            return None, (403, 'このフォルダには追加できません')
        if not os.path.isdir(self.server.root):
            return None, (503, 'HDDが見つかりません（接続されているか確認してください）')
        d = self.safe_path(rel, self.server.root)
        if not d or not os.path.isdir(d) or (parts and parts[0] in SKIP_DIRS):
            return None, (404, 'フォルダが見つかりません')
        return d, None

    def api_upload(self, q):
        self.close_connection = True       # 途中で断った場合に本文が残らないよう、毎回接続を閉じる
        d, err = self.write_dir(q.get('path', [''])[0])
        if err:
            return self.send_json({'error': err[1]}, err[0])
        name = clean_name(q.get('name', [''])[0])
        if not name or not kind_of(name):
            return self.send_json({'error': '写真・動画のファイルだけ追加できます'}, 400)
        try:
            n = int(self.headers.get('Content-Length') or -1)
        except ValueError:
            n = -1
        if n < 0:
            return self.send_json({'error': 'ファイルの大きさがわかりません'}, 411)
        if n > MAX_UPLOAD:
            return self.send_json({'error': 'ファイルが大きすぎます'}, 413)
        if shutil.disk_usage(d).free < n + FREE_MARGIN:
            return self.send_json({'error': 'HDDの空き容量が足りません'}, 507)
        tmp = os.path.join(d, '.upload-' + secrets.token_hex(8) + '.part')
        try:
            left = n
            with open(tmp, 'xb') as f:
                while left > 0:
                    buf = self.rfile.read(min(CHUNK, left))
                    if not buf:
                        raise ConnectionError('途中で切れました')
                    f.write(buf)
                    left -= len(buf)
                f.flush(); os.fsync(f.fileno())
            try:
                mt = int(q.get('mtime', ['0'])[0]) / 1000
            except ValueError:
                mt = 0
            if 0 < mt < time.time() + 86400:
                os.utime(tmp, (mt, mt))
            stem, ext = os.path.splitext(name)
            with NAME_LOCK:
                final, i = name, 2
                while os.path.lexists(os.path.join(d, final)):
                    final = f'{stem} ({i}){ext}'; i += 1
                os.rename(tmp, os.path.join(d, final))
        except Exception as e:
            try: os.remove(tmp)
            except OSError: pass
            if isinstance(e, (BrokenPipeError, ConnectionResetError)):
                raise
            return self.send_json({'error': '保存できませんでした（' + type(e).__name__ + '）'}, 500)
        st = os.stat(os.path.join(d, final))
        self.send_json({'ok': True, 'name': final, 'size': st.st_size, 'mtime': int(st.st_mtime * 1000)})

    def api_mkdir(self, body):
        d, err = self.write_dir(str(body.get('path', '')))
        if err:
            return self.send_json({'error': err[1]}, err[0])
        name = clean_name(body.get('name', ''))
        if not name or name in SKIP_DIRS:
            return self.send_json({'error': 'この名前は使えません'}, 400)
        with NAME_LOCK:
            full = os.path.join(d, name)
            if os.path.lexists(full):
                return self.send_json({'error': '同じ名前のフォルダ（またはファイル）がすでにあります'}, 409)
            try:
                os.mkdir(full)
            except OSError as e:
                return self.send_json({'error': '作れませんでした（' + type(e).__name__ + '）'}, 500)
        self.send_json({'ok': True, 'name': name})

    # ---- 削除（ゴミ箱）・移動・名前変更 ----
    def item_path(self, rel):
        """変更してよい既存の写真・動画・フォルダの実パス。だめなら (None, (status, message))"""
        a = self.server.auth
        if a and not self.current_user():
            return None, (401, 'ログインしてください')
        parts = [p for p in str(rel).split('/') if p]
        if not parts or (a and len(parts) < 2):
            return None, (403, 'いちばん上のフォルダは変更できません')
        if not self.allowed('/'.join(parts)):
            return None, (403, 'このフォルダは変更できません')
        if not os.path.isdir(self.server.root):
            return None, (503, 'HDDが見つかりません（接続されているか確認してください）')
        full = self.safe_path('/'.join(parts), self.server.root)
        raw = os.path.join(self.server.root, *parts)
        if not full or not os.path.lexists(raw) or os.path.islink(raw) or parts[0] in SKIP_DIRS:
            return None, (404, '見つかりません')
        if os.path.isfile(full) and not kind_of(parts[-1]):
            return None, (403, '写真・動画以外のファイルは変更できません')
        return full, None

    def trash_dir(self):
        return os.path.join(self.server.root, TRASH)

    def free_name(self, d, name, isdir):
        stem, ext = (name, '') if isdir else os.path.splitext(name)
        final, i = name, 2
        while os.path.lexists(os.path.join(d, final)):
            final = f'{stem} ({i}){ext}'; i += 1
        return final

    def rel_of(self, full):
        return os.path.relpath(full, os.path.realpath(self.server.root)).replace(os.sep, '/')

    def api_trash(self, body):
        items = body.get('items') or []
        if not isinstance(items, list) or not 0 < len(items) <= 2000:
            return self.send_json({'error': '対象がありません'}, 400)
        done, errors = [], []
        uid = self.current_user()
        for rel in items:
            full, err = self.item_path(rel)
            if err:
                errors.append(f'{rel}：{err[1]}'); continue
            tid = time.strftime('%Y%m%d-%H%M%S') + '-' + secrets.token_hex(4)
            box = os.path.join(self.trash_dir(), tid)
            try:
                with NAME_LOCK:
                    os.makedirs(box)
                    isdir = os.path.isdir(full)
                    size = 0 if isdir else os.path.getsize(full)
                    name = os.path.basename(full)
                    os.rename(full, os.path.join(box, name))
                    meta = {'orig': self.rel_of(full), 'name': name, 'kind': 'dir' if isdir else kind_of(name),
                            'size': size, 'at': int(time.time() * 1000), 'by': uid}
                    with open(os.path.join(self.trash_dir(), tid + '.json'), 'w', encoding='utf-8') as f:
                        json.dump(meta, f, ensure_ascii=False)
                done.append(rel)
            except OSError as e:
                errors.append(f'{rel}：ゴミ箱に移せませんでした（{type(e).__name__}）')
        self.send_json({'ok': True, 'done': done, 'errors': errors})

    def trash_items(self):
        """見てよいゴミ箱の中身 [(id, meta)]（新しい順）"""
        out = []
        t = self.trash_dir()
        if not os.path.isdir(t):
            return out
        for fn in os.listdir(t):
            if not fn.endswith('.json'):
                continue
            tid = fn[:-5]
            try:
                with open(os.path.join(t, fn), encoding='utf-8') as f:
                    m = json.load(f)
            except (OSError, ValueError):
                continue
            if self.allowed(m.get('orig', '')) and os.path.lexists(os.path.join(t, tid, m.get('name', ''))):
                out.append((tid, m))
        out.sort(key=lambda x: -x[1].get('at', 0))
        return out

    def api_trash_list(self):
        a = self.server.auth
        if a and not self.current_user():
            return self.send_json({'error': 'ログインしてください'}, 401)
        names = {k: v['display'] for k, v in a.data['users'].items()} if a else {}
        items = [{'id': tid, 'name': m['name'], 'orig': m['orig'], 'kind': m.get('kind'), 'size': m.get('size', 0),
                  'at': m.get('at', 0), 'by': names.get(m.get('by'), '')} for tid, m in self.trash_items()]
        self.send_json({'items': items})

    def api_trash_act(self, body, restore):
        a = self.server.auth
        if a and not self.current_user():
            return self.send_json({'error': 'ログインしてください'}, 401)
        want = set(body.get('ids') or [])
        done, errors = [], []
        t = self.trash_dir()
        for tid, m in self.trash_items():
            if tid not in want:
                continue
            src = os.path.join(t, tid, m['name'])
            try:
                with NAME_LOCK:
                    if restore:
                        parts = [p for p in m['orig'].split('/') if p]
                        parent = os.path.join(self.server.root, *parts[:-1])
                        if not self.safe_path('/'.join(parts[:-1]), self.server.root):
                            raise OSError('戻し先が不正です')
                        os.makedirs(parent, exist_ok=True)
                        final = self.free_name(parent, m['name'], os.path.isdir(src))
                        os.rename(src, os.path.join(parent, final))
                    else:
                        if os.path.isdir(src) and not os.path.islink(src):
                            shutil.rmtree(src)
                        else:
                            os.remove(src)
                    os.remove(os.path.join(t, tid + '.json'))
                    try: os.rmdir(os.path.join(t, tid))
                    except OSError: pass
                done.append(tid)
            except OSError as e:
                errors.append(f'{m["name"]}：{e}')
        self.send_json({'ok': True, 'done': done, 'errors': errors})

    def api_move(self, body):
        dest, err = self.write_dir(str(body.get('dest', '')))
        if err:
            return self.send_json({'error': err[1]}, err[0])
        items = body.get('items') or []
        if not isinstance(items, list) or not 0 < len(items) <= 2000:
            return self.send_json({'error': '対象がありません'}, 400)
        done, errors, renamed = [], [], []
        for rel in items:
            full, e = self.item_path(rel)
            if e:
                errors.append(f'{rel}：{e[1]}'); continue
            name = os.path.basename(full)
            if os.path.dirname(full) == dest:
                errors.append(f'{name}：すでにこのフォルダにあります'); continue
            if os.path.isdir(full) and (dest == full or dest.startswith(full + os.sep)):
                errors.append(f'{name}：フォルダをその中には移せません'); continue
            try:
                with NAME_LOCK:
                    final = self.free_name(dest, name, os.path.isdir(full))
                    os.rename(full, os.path.join(dest, final))
                done.append(rel)
                if final != name:
                    renamed.append(f'{name} → {final}')
            except OSError as ex:
                errors.append(f'{name}：移せませんでした（{type(ex).__name__}）')
        self.send_json({'ok': True, 'done': done, 'errors': errors, 'renamed': renamed})

    def api_rename(self, body):
        full, err = self.item_path(body.get('path', ''))
        if err:
            return self.send_json({'error': err[1]}, err[0])
        name = clean_name(body.get('name', ''))
        isdir = os.path.isdir(full)
        if not name or (isdir and name in SKIP_DIRS):
            return self.send_json({'error': 'この名前は使えません'}, 400)
        if not isdir and not kind_of(name):
            return self.send_json({'error': '写真・動画の拡張子（.jpg など）を残してください'}, 400)
        new = os.path.join(os.path.dirname(full), name)
        with NAME_LOCK:
            if os.path.lexists(new) and not os.path.samefile(new, full):
                return self.send_json({'error': '同じ名前がすでにあります'}, 409)
            try:
                os.rename(full, new)
            except OSError as e:
                return self.send_json({'error': '名前を変えられませんでした（' + type(e).__name__ + '）'}, 500)
        self.send_json({'ok': True, 'name': name})

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
                info = {'app': 'photo-album-server', 'version': 2, 'name': os.path.basename(root.rstrip('/')),
                        'available': os.path.isdir(root), 'auth': bool(self.server.auth)}
                if self.server.auth:
                    uid = self.current_user()
                    info['users'] = self.server.auth.users_public()
                    info['me'] = {'id': uid, 'name': self.server.auth.data['users'][uid]['display']} if uid else None
                return self.send_json(info)
            if path == '/api/list':
                rel = q.get('path', [''])[0]
                if not self.allowed(rel):
                    return self.send_json({'error': 'ログインしてください'}, 401)
                return self.api_list(rel)
            if path == '/api/trash':
                return self.api_trash_list()
            if path.startswith('/trashthumb/'):
                tid = path.split('/', 2)[2]
                for t, m in self.trash_items():
                    if t == tid and m.get('kind') in ('image', 'video'):
                        return self.send_thumb(os.path.join(self.trash_dir(), t, m['name']), head)
                return self.send_err(404, 'not found')
            if path.startswith('/media/') or path.startswith('/thumb/'):
                rel = path.split('/', 2)[2]
                if not self.allowed(rel) or not [p for p in rel.split('/') if p][1:]:
                    return self.send_err(401, 'login required')
                if path.startswith('/media/'):
                    return self.send_file(self.safe_path(rel, self.server.root), head, media=True, dl='dl' in q)
                return self.send_thumb(self.safe_path(rel, self.server.root), head)
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
                            if e.name not in SKIP_DIRS and (rel.strip('/') or self.allowed(e.name)):
                                dirs.append(e.name)
                        elif e.is_file(follow_symlinks=False) and kind_of(e.name) and (rel.strip('/') or not self.server.auth):
                            st = e.stat()
                            files.append({'name': e.name, 'size': st.st_size, 'mtime': int(st.st_mtime * 1000)})
                    except OSError:
                        continue
        except PermissionError:
            return self.send_json({'error': 'このフォルダは開けません（アクセス権がありません）'}, 403)
        self.send_json({'dirs': dirs, 'files': files})

    # ---- ファイル送信（動画の途中再生に必要な Range 要求に対応） ----
    def send_file(self, full, head, media, dl=False):
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
        if dl:
            self.send_header('Content-Disposition', "attachment; filename*=UTF-8''" + urllib.parse.quote(os.path.basename(full)))
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
    ap.add_argument('--host', default='127.0.0.1', help='待ち受けるアドレス。カンマ区切りで複数可')
    ap.add_argument('--cache', default=os.path.expanduser('~/Library/Caches/AlbumServer'))
    ap.add_argument('--users', default='', help='家族ごとのログイン設定（users.json）。指定するとログインが必要になる')
    a = ap.parse_args()
    auth = Auth(a.users) if a.users else None
    os.makedirs(a.cache, exist_ok=True)
    servers = []
    for host in [h.strip() for h in a.host.split(',') if h.strip()]:   # 例：--host 127.0.0.1,100.x.x.x
        srv = ThreadingHTTPServer((host, a.port), Handler)
        srv.daemon_threads = True
        srv.root = os.path.abspath(a.root)
        srv.app = os.path.abspath(a.app)
        srv.cache = a.cache
        srv.auth = auth
        servers.append(srv)
        print(f'AlbumServer: http://{host}:{a.port}/  root={srv.root}', flush=True)
    for srv in servers[1:]:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    servers[0].serve_forever()

if __name__ == '__main__':
    main()
