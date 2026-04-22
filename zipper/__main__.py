"""CLI entrypoint for zipper: python -m zipper."""

import argparse
import getpass
import logging
import sys
from pathlib import Path

from zipper.core import create_secure_encrypted_zip, extract_secure_encrypted_zip


def main() -> None:
    logging.basicConfig(format="%(message)s", level=logging.INFO)
    parser = argparse.ArgumentParser(description="暗号化ZIPファイルの作成・解凍ツール")
    parser.add_argument(
        "-c",
        "--create",
        dest="operation",
        action="store_const",
        const="create",
        help="暗号化圧縮モード",
    )
    parser.add_argument(
        "-x",
        "--extract",
        dest="operation",
        action="store_const",
        const="extract",
        help="解凍モード",
    )
    parser.add_argument(
        "target",
        help="圧縮対象のパス(-cの場合)またはZIPファイルのパス(-xの場合)",
    )
    parser.add_argument(
        "output",
        nargs="?",
        help="出力先のパス(省略可能)",
    )
    parser.add_argument(
        "-e",
        "--encrypt-filenames",
        action="store_true",
        help="ファイル名とディレクトリ名も暗号化する(-cの場合のみ有効)",
    )

    args = parser.parse_args()

    try:
        if not args.operation:
            parser.error("操作を指定してください(-c または -x)")

        if args.operation == "create":
            password = getpass.getpass("圧縮パスワードを入力してください: ").encode(
                "utf-8"
            )
            password_confirm = getpass.getpass(
                "圧縮パスワードを再入力してください: "
            ).encode("utf-8")

            if password != password_confirm:
                print("エラー: パスワードが一致しません。")
                sys.exit(1)

            target_path = Path(args.target).resolve()
            output_zip_path = Path(args.output).resolve() if args.output else None
            zip_path = create_secure_encrypted_zip(
                target_path,
                password,
                output_zip_path,
                encrypt_filenames=args.encrypt_filenames,
            )
            print(f"暗号化完了: {zip_path}")
            if args.encrypt_filenames:
                print("注意: ファイル名とディレクトリ名も暗号化されています。")

        elif args.operation == "extract":
            password = getpass.getpass("解凍パスワードを入力してください: ").encode(
                "utf-8"
            )

            zip_filepath = Path(args.target).resolve()
            extract_dir = Path(args.output).resolve() if args.output else None
            extract_secure_encrypted_zip(zip_filepath, password, extract_dir)
            print("解凍完了")

    except Exception as e:  # noqa: BLE001
        print(f"エラー: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
