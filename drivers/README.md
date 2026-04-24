# Npcapインストーラー配置先

`scripts\build_release.ps1 -DownloadNpcap` を実行すると、公式リリースアーカイブからNpcapインストーラーを取得し、このフォルダーへ保存します。

手動で配置する場合は、`npcap-*.exe` という名前でこのフォルダーに置いてください。ビルド時に `dist\LLDPバイト送受信ツール\drivers` へコピーされます。
