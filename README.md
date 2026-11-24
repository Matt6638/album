# フォトアルバム

外付けハードディスクなどのフォルダを選ぶと、その中のフォルダをアルバムとして表示するWebアプリです。

- 写真（JPEG・PNG・HEIC・WebP など）と動画（MP4・MOV など）に対応
- 写真・動画はブラウザ内で読み込むだけで、インターネットへ送信しません
- Chrome / Edge では選んだフォルダを記憶し、次回から一覧から開けます
- 宿泊データ（宿泊記録.json）を読み込むと、アルバムの表紙に宿泊ホテルを表示し、宿泊マップで一覧できます（データはブラウザ内にのみ保存。このリポジトリには含みません）

公開URL: https://matt6638.github.io/album/

地図は [Leaflet](https://leafletjs.com/)（BSD-2-Clause）と Leaflet.markercluster（MIT）を同梱し、背景地図に[地理院タイル](https://maps.gsi.go.jp/development/ichiran.html)を使用しています。

HEIC画像の変換に [heic2any](https://github.com/alexcorvi/heic2any)（MIT License）を同梱しています（`vendor/`）。
