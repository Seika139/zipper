# Changelog

このプロジェクトの注目すべき変更はこのファイルで文書化されています。

フォーマットは [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) に基づいており、
このプロジェクトは [セマンティック バージョニング](https://semver.org/lang/ja/spec/v2.0.0.html) を遵守しています。

## [Unreleased]

### Fixed

- `extract_secure_encrypted_zip` が既存ディレクトリへの上書き解凍途中で失敗した際、上書き対象だった既存ファイルを `cleanup()` が `unlink()` してデータを失う問題を修正。二相コミット方式 (staging への復号 → 既存ファイルを backup へ退避してから commit → 失敗時に backup から rename で完全復元) に書き換えた

### Changed

- `extract_secure_encrypted_zip` が解凍前に全エントリのパスを `_safe_join` で検証するように変更 (Phase 0 pre-flight validation)。途中で symlink/path traversal を検出しても **書き込みゼロのまま abort** する
- 既存ディレクトリへの解凍は merge セマンティクスとして明文化: ZIP に含まれるファイルだけが対象になり、ZIP に含まれない既存ファイルは保護される

### Added

- ロールバックの不変条件を検証するテストを追加 (上書き失敗時の既存ファイル復元、symlink エラー時の既存ファイル保護、staging/backup の作業 dir リーク検出、path traversal abort 後の既存ファイル保護)

## [0.1.0] - 2026-04-24

### Security

- Zip Slip 脆弱性を修正 (`..`, 絶対パス, ドライブ文字, 途中コンポーネントの symlink 経由での `extract_dir` 外への書き込みを拒否)
- メタデータの `kdf.iterations` をホワイトリスト (`{390_000, 600_000}`) で検証し、悪意ある値での CPU DoS / 脆弱鍵生成を防止
- ルート直下のユーザファイル名 `metadata` を予約名衝突として作成時に拒否 (データ破損の回避)
- `_load_metadata` の `metadata.salt` 探索を完全一致に変更し、`dir/metadata.salt` のような名前の誤検出を回避

### Changed

- サポート対象を Python 3.13 以上に変更 (ruff/mypy の `target-version` と整合)
- PBKDF2 iterations を 390,000 から 600,000 に引き上げ (OWASP 2023 推奨値)
- メタデータに `version` と `kdf.iterations` を記録し、将来のパラメータ変更を後方互換で可能にする
- ZIP の格納方式を `ZIP_DEFLATED` から `ZIP_STORED` に変更 (Fernet 暗号文は deflate で縮まないため)

### Added

- 旧 0.1.0 製 ZIP (iterations=390,000) の自動判別での復号対応
- `_decrypt_single_file` の中間ディレクトリを cleanup 対象に追加
- 攻撃面テスト (path traversal, 絶対パス, symlink, 予約名衝突, 不正 iterations)

### Fixed

- `_decrypt_single_file` が `InvalidToken` 以外の例外を silent に握りつぶしていた問題を修正
- `extract_secure_encrypted_zip` が任意の例外を `ValueError` にラップして traceback を失わせていた問題を修正
- CLI でパスワード入力中に Ctrl+C / Ctrl+D を押した際、traceback や "エラー: " の空メッセージが出ていた問題を修正。`キャンセルしました。` と出して exit code 130 で終了する

## [0.1.0] - 2026-04-20

### Added

- [scribe](https://github.com/Seika139/scribe) リポジトリから暗号化 ZIP 機能を分離して独立リポジトリとして構成
- パスワードを引数として受け取る API に変更し、ライブラリとしての利用性を向上
- `_load_metadata`, `_decrypt_single_file`, `_resolve_zip_filename` へのリファクタリングでネストを軽減
- CI ワークフロー (uv-qualify, lint-markdown, update-version) を追加
- Dependabot による依存管理を設定

### Removed

- 未使用だった `common_salt` をメタデータから削除
