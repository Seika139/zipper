# zipper

パスワードベースの暗号化 ZIP アーカイバです。
ファイル内容だけでなく、ファイル名・ディレクトリ名の暗号化にも対応しています。

## Features

- PBKDF2-HMAC-SHA256 (600,000 iterations) + Fernet (AES-128-CBC + HMAC-SHA256) による暗号化
- `.gitignore` ルールに従ったファイル除外
- ファイル名・ディレクトリ名の暗号化オプション
- Windows / macOS / Linux 対応
- 旧フォーマット (0.1.0 時代の 390,000 iterations) の ZIP も復号可能

## Requirements

- Python 3.13 以上

## Installation

```bash
uv add git+https://github.com/Seika139/zipper.git
```

## Usage

### CLI

```bash
# 暗号化 (ファイル内容のみ)
python -m zipper -c /path/to/target

# 暗号化 (ファイル名・ディレクトリ名も暗号化)
python -m zipper -c -e /path/to/target

# 復号
python -m zipper -x /path/to/archive_encrypted.zip
```

### mise タスク

`mise run encrypt` はファイル名暗号化 (`-e`) が **デフォルトで有効** です。

```bash
mise run encrypt /path/to/target
mise run decrypt /path/to/archive_encrypted.zip
```

### ライブラリとして

```python
from zipper import create_secure_encrypted_zip, extract_secure_encrypted_zip

# 暗号化
zip_path = create_secure_encrypted_zip(
    target=Path("/path/to/dir"),
    password=b"my_password",
)

# 復号
extract_secure_encrypted_zip(
    zip_filepath=zip_path,
    password=b"my_password",
)
```

## Security

このライブラリは **自分で作成した ZIP を自分で復号する用途** を想定しています。
公開ライブラリとしては以下の防御を実装しています:

- Zip Slip 攻撃の防止 (`..`、絶対パス、ドライブ文字、途中コンポーネントの symlink を拒否)
- メタデータ改竄検知 (`kdf.iterations` のホワイトリスト検証)
- 予約名衝突の検知 (ルート直下に `metadata` という名前のファイルは作成時に拒否)

一方で、**以下は明示的に防御対象外** です:

- **Zip Bomb / メモリ枯渇**: `encrypt_file` / `decrypt_file` はファイル全体をメモリに読み込みます。巨大な暗号化 ZIP を復号するとメモリ使用量がそのぶん跳ね上がります。信頼できない送信元から受け取った ZIP を復号する運用は想定していません。
- **空パスワード**: 空文字のパスワードでも暗号化できます。運用で注意してください。
- **タイミング攻撃**: legacy iteration のフォールバック試行で KDF の実行回数が変わるため、ZIP のフォーマット世代をタイミングで推定される可能性があります。鍵自体は漏れません。

## 仕様と注意点

### 出力 ZIP ファイル名の解決

`create_secure_encrypted_zip` の `zip_filename` に相対パスを渡した場合、
解決基準は **カレントディレクトリではなく `target.parent`** です。
CLI から `python -m zipper -c /some/dir ./out.zip` を叩いた場合は、
argparse 受領後に `Path.resolve()` されるため結果的にカレント基準になりますが、
ライブラリ API を直接呼ぶ際は引数に絶対パスを渡すことを推奨します。

### アーカイブ対象

- `.git` ディレクトリは常にスキップされます。
- 対象ディレクトリ配下に `.gitignore` がある場合、そのルールに従って除外されます。
- **空ディレクトリは ZIP に含まれません**。`_add_file` がファイル単位でのみエントリを書き込む仕様のため、復号後に空だったディレクトリは再現されません。
- **シンボリックリンクはリンク先の内容として扱われます**。`Path.is_file()` が symlink-to-file に対して True を返すため、リンク先の内容がコピーされ、リンク自体は保持されません。

### 後方互換性

- 0.2.0 以降で生成された ZIP は、メタデータに `version` と `kdf.iterations` を含みます。
- 0.1.0 で生成された ZIP (iterations=390,000) も自動判別で復号できます。
- 0.2.0 以降で生成された ZIP は、0.1.0 では復号できません（iterations が異なるため）。

## Development

```bash
mise run init     # 依存インストール
mise run check    # ruff + mypy
mise run test     # pytest
mise run format   # ruff format + fix
```

## License

[MIT](LICENSE)
