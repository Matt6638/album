#!/usr/bin/env python3
"""家族ごとの招待コードを発行する（users.json を更新し、コードは指定したファイルにだけ書き出す）

使い方:
  python3 make_invites.py --users users.json --out 招待コード.txt          # パスワード未設定の人に発行
  python3 make_invites.py --users users.json --out 招待コード.txt --reset ID  # その人のパスワードを消して再発行
"""
import argparse, json, os, secrets, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from album_server import pw_hash

ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'   # 見間違えやすい 0/O, 1/I は使わない

def new_code():
    c = ''.join(secrets.choice(ALPHABET) for _ in range(8))
    return c[:4] + '-' + c[4:]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--users', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--reset', action='append', default=[])
    a = ap.parse_args()
    data = json.load(open(a.users, encoding='utf-8'))
    lines = []
    for uid, u in data['users'].items():
        if uid in a.reset:
            u.pop('pw', None)
        if u.get('pw'):
            continue
        code = new_code()
        u['invite'] = pw_hash(code.replace('-', ''))
        lines.append(f"{u['display']}：{code}")
    tmp = a.users + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, a.users)
    with open(a.out, 'w', encoding='utf-8') as f:
        f.write('家族アルバムの招待コード（1人1回だけ使えます。パスワードを設定したら不要になります）\n\n' + '\n'.join(lines) + '\n')
    os.chmod(a.out, 0o600)
    print(f'{len(lines)}人分の招待コードを書き出しました: {a.out}')

if __name__ == '__main__':
    main()
