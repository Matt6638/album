#!/usr/bin/env python3
"""家族ごとの招待コードを発行する（users.json を更新し、コードは指定したファイルにだけ書き出す）

使い方:
  python3 make_invites.py --users users.json --out 招待コード.txt            # パスワード未設定の全員に発行（初回用）
  python3 make_invites.py --users users.json --out 招待コード.txt --reset ID  # その人だけパスワードを消して再発行
                                                                             # （ほかの人のコードはそのまま。ログイン中の端末も締め出す）
※ 実行中のサーバーは users.json を読み直さないので、サーバーを止めてから実行し、終わったら起動し直す
"""
import argparse, json, os, re, secrets, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from album_server import pw_hash

ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'   # 見間違えやすい 0/O, 1/I は使わない
HEAD = '家族アルバムの招待コード（1人1回だけ使えます。パスワードを設定したら不要になります）'

def new_code():
    c = ''.join(secrets.choice(ALPHABET) for _ in range(8))
    return c[:4] + '-' + c[4:]

def write_private(path, text):
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        f.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--users', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--reset', action='append', default=[])
    a = ap.parse_args()
    data = json.load(open(a.users, encoding='utf-8'))
    for uid in a.reset:
        if uid not in data['users']:
            sys.exit(f'見つからないID: {uid}')
    issued = {}
    for uid, u in data['users'].items():
        if a.reset:
            if uid not in a.reset:
                continue            # 再発行のときは、指定した人以外に触らない
            u.pop('pw', None)
        elif u.get('pw'):
            continue
        code = new_code()
        u['invite'] = pw_hash(code.replace('-', ''))
        issued[u['display']] = code
    write_private(a.users, json.dumps(data, ensure_ascii=False, indent=1))
    # 再発行した人のログイン中の端末を締め出す
    sess = os.path.join(os.path.dirname(os.path.abspath(a.users)), 'sessions.json')
    if a.reset and os.path.exists(sess):
        s = json.load(open(sess, encoding='utf-8'))
        s = {k: v for k, v in s.items() if v.get('user') not in a.reset}
        write_private(sess, json.dumps(s, ensure_ascii=False, indent=1))
    # 招待コードの一覧：再発行のときは、その人の行だけ差し替える
    lines = []
    if a.reset and os.path.exists(a.out):
        for ln in open(a.out, encoding='utf-8').read().splitlines():
            m = re.match(r'^(.+?)：', ln)
            if m and m.group(1) not in issued:
                lines.append(ln)
    lines += [f'{n}：{c}' for n, c in issued.items()]
    write_private(a.out, HEAD + '\n\n' + '\n'.join(lines) + '\n')
    print(f'{len(issued)}人分の招待コードを書き出しました（{"、".join(issued)}）: {a.out}')

if __name__ == '__main__':
    main()
