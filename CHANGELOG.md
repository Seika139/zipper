# Changelog

このプロジェクトの注目すべき変更はこのファイルで文書化されています。

フォーマットは [Keep a Changelog](https://keepachangelog.com/ja/1.1.0/) に基づいており、
このプロジェクトは [セマンティック バージョニング](https://semver.org/lang/ja/spec/v2.0.0.html) を遵守しています。

## [Unreleased]

### Changed

- PBKDF2 iterations を 390,000 から 600,000 に引き上げ (OWASP 2023 推奨値)
- メタデータに `version` と `kdf.iterations` を記録し、将来のパラメータ変更を後方互換で可能にする
- ZIP の格納方式を `ZIP_DEFLATED` から `ZIP_STORED` に変更 (Fernet 暗号文は deflate で縮まないため)

### Added

- 旧 0.1.0 製 ZIP (iterations=390,000) の自動判別での復号対応
- `_decrypt_single_file` の中間ディレクトリを cleanup 対象に追加

### Fixed

- `_decrypt_single_file` が `InvalidToken` 以外の例外を silent に握りつぶしていた問題を修正
- `extract_secure_encrypted_zip` が任意の例外を `ValueError` にラップして traceback を失わせていた問題を修正

## [0.1.0] - 2026-04-20

### Added

- [scribe](https://github.com/Seika139/scribe) リポジトリから暗号化 ZIP 機能を分離して独立リポジトリとして構成
- パスワードを引数として受け取る API に変更し、ライブラリとしての利用性を向上
- `_load_metadata`, `_decrypt_single_file`, `_resolve_zip_filename` へのリファクタリングでネストを軽減
- CI ワークフロー (uv-qualify, lint-markdown, update-version) を追加
- Dependabot による依存管理を設定

### Removed

- 未使用だった `common_salt` をメタデータから削除
