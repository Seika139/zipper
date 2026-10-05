"""CLI entrypoint for zipper: python -m zipper."""

import argparse
import getpass
import logging
import os
import subprocess  # ruff: ignore[suspicious-subprocess-import]
import sys
from pathlib import Path

from zipper.core import create_secure_encrypted_zip, extract_secure_encrypted_zip


def _run_git(target: Path, *args: str) -> str:
    """`git -C <target> <args>` を実行し、stdout を返す。

    Returns:
        str: コマンドの標準出力

    Raises:
        ValueError: git コマンドが見つからない、対象が git リポジトリでない、
            HEAD が存在しない(コミットが1つもない)、またはその他の git エラー
    """
    try:
        result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
            ["git", "-C", str(target), *args],  # ruff: ignore[start-process-with-partial-path]
            check=True,
            capture_output=True,
        )
    except FileNotFoundError as e:
        msg = "git コマンドが見つかりません。git をインストールしてください。"
        raise ValueError(msg) from e
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode("utf-8", errors="replace")
        if "not a git repository" in stderr.lower():
            msg = f"'{target}' は git リポジトリではありません。"
            raise ValueError(msg) from e
        if (
            "ambiguous argument 'HEAD'" in stderr
            or "unknown revision" in stderr
            or "bad revision" in stderr
        ):
            msg = "HEAD が存在しません(コミットが1つもありません)。"
            raise ValueError(msg) from e
        msg = f"git コマンドが失敗しました: {stderr.strip()}"
        raise ValueError(msg) from e
    return os.fsdecode(result.stdout)


def list_git_changed_files(target: Path, mode: str) -> list[str]:
    """Git の差分になっているファイルを列挙する(比較先は HEAD 固定)。

    Args:
        target: git リポジトリ(またはそのサブディレクトリ)のパス
        mode: "staged" または "worktree"

    Returns:
        list[str]: target 基準の相対パス一覧(重複排除、安定順)

    Raises:
        ValueError: git コマンドの実行に失敗した場合、または差分が空の場合
    """
    changed: list[str] = []
    if mode == "staged":
        out = _run_git(
            target,
            "diff",
            "-z",
            "--name-only",
            "--relative",
            "--no-renames",
            "--diff-filter=d",
            "--cached",
        )
        changed.extend(p for p in out.split("\0") if p)
    else:
        worktree_out = _run_git(
            target,
            "diff",
            "-z",
            "--name-only",
            "--relative",
            "--no-renames",
            "--diff-filter=d",
            "HEAD",
        )
        changed.extend(p for p in worktree_out.split("\0") if p)
        untracked_out = _run_git(
            target,
            "ls-files",
            "-z",
            "--others",
            "--exclude-standard",
        )
        changed.extend(p for p in untracked_out.split("\0") if p)

    deduped = list(dict.fromkeys(changed))
    if not deduped:
        msg = "git の差分が見つかりません。"
        raise ValueError(msg)
    return deduped


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
    parser.add_argument(
        "--git-diff",
        nargs="?",
        choices=["staged", "worktree"],
        const="worktree",
        default=None,
        help=(
            "git の差分になっているファイルだけを圧縮する(-cの場合のみ有効)。"
            "比較先は HEAD 固定。'staged' はステージ済みの差分、"
            "'worktree' (省略時のデフォルト) はステージ済み・未ステージ・"
            "未追跡ファイルすべての差分を対象にする"
        ),
    )

    args = parser.parse_args()

    try:
        if not args.operation:
            parser.error("操作を指定してください(-c または -x)")

        if args.git_diff is not None:
            if args.operation != "create":
                parser.error("--git-diff は -c (作成モード) の場合のみ指定できます")
            if not Path(args.target).resolve().is_dir():
                parser.error("--git-diff はディレクトリに対してのみ指定できます")

        if args.operation == "create":
            target_path = Path(args.target).resolve()

            git_files: list[str] | None = None
            git_head: str | None = None
            if args.git_diff is not None:
                git_head = _run_git(target_path, "rev-parse", "HEAD").strip()
                git_files = list_git_changed_files(target_path, args.git_diff)

            password = getpass.getpass("圧縮パスワードを入力してください: ").encode(
                "utf-8"
            )
            password_confirm = getpass.getpass(
                "圧縮パスワードを再入力してください: "
            ).encode("utf-8")

            if password != password_confirm:
                print("エラー: パスワードが一致しません。")
                sys.exit(1)

            output_zip_path = Path(args.output).resolve() if args.output else None
            extra_metadata = (
                {"git": {"head": git_head, "mode": args.git_diff}}
                if args.git_diff is not None
                else None
            )
            zip_path = create_secure_encrypted_zip(
                target_path,
                password,
                output_zip_path,
                encrypt_filenames=args.encrypt_filenames,
                files=git_files,
                extra_metadata=extra_metadata,
            )
            print(f"暗号化完了: {zip_path}")
            if args.encrypt_filenames:
                print("注意: ファイル名とディレクトリ名も暗号化されています。")
            if args.git_diff == "staged":
                print(
                    "注意: --git-diff staged でも ZIP に入る内容は working tree "
                    "のものです(index の内容ではありません)。"
                )

        elif args.operation == "extract":
            password = getpass.getpass("解凍パスワードを入力してください: ").encode(
                "utf-8"
            )

            zip_filepath = Path(args.target).resolve()
            extract_dir = Path(args.output).resolve() if args.output else None
            extract_secure_encrypted_zip(zip_filepath, password, extract_dir)
            print("解凍完了")

    except (KeyboardInterrupt, EOFError):
        print("\nキャンセルしました。")
        sys.exit(130)
    except Exception as e:  # ruff: ignore[blind-except]
        print(f"エラー: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
