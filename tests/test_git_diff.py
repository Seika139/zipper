"""`--git-diff` モード (`list_git_changed_files` と `files` 経由の create) のテスト。"""

import os
import subprocess  # ruff: ignore[suspicious-subprocess-import]
from pathlib import Path

import pytest

from zipper.__main__ import list_git_changed_files
from zipper.core import create_secure_encrypted_zip, extract_secure_encrypted_zip

PASSWORD = b"test_password"


def _git_env(repo: Path) -> dict[str, str]:
    """ユーザーのグローバル git 設定から分離した環境変数を返す。

    設定ファイルは repo の外(親ディレクトリ)に置き、worktree を汚さない。

    Returns:
        dict[str, str]: `subprocess.run` に渡す env
    """
    config_path = repo.parent / f".gitconfig-empty-{repo.name}"
    config_path.touch()
    return {
        **os.environ,
        "GIT_CONFIG_GLOBAL": str(config_path),
        "GIT_CONFIG_NOSYSTEM": "1",
    }


def _git(repo: Path, *args: str) -> None:
    subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]
        ["git", "-C", str(repo), *args],  # ruff: ignore[start-process-with-partial-path]
        check=True,
        capture_output=True,
        env=_git_env(repo),
    )


def _init_repo(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q", "-b", "main")
    _git(
        repo,
        "-c",
        "user.email=test@example.com",
        "-c",
        "user.name=test",
        "commit",
        "--allow-empty",
        "-q",
        "-m",
        "init",
    )


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    _init_repo(repo)
    return repo


def test_worktree_mode_lists_staged_unstaged_untracked(git_repo: Path) -> None:
    (git_repo / "tracked.txt").write_text("base", encoding="utf-8")
    _git(git_repo, "add", "tracked.txt")
    _git(
        git_repo,
        "-c",
        "user.email=test@example.com",
        "-c",
        "user.name=test",
        "commit",
        "-q",
        "-m",
        "add tracked",
    )

    (git_repo / "staged.txt").write_text("staged", encoding="utf-8")
    _git(git_repo, "add", "staged.txt")

    (git_repo / "tracked.txt").write_text("modified", encoding="utf-8")

    (git_repo / "untracked.txt").write_text("untracked", encoding="utf-8")

    (git_repo / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (git_repo / "ignored.txt").write_text("should be excluded", encoding="utf-8")

    result = set(list_git_changed_files(git_repo, "worktree"))
    # .gitignore 自体は untracked かつどのルールにも一致しないため列挙される
    assert result == {"staged.txt", "tracked.txt", "untracked.txt", ".gitignore"}
    assert "ignored.txt" not in result


def test_staged_mode_lists_only_staged(git_repo: Path) -> None:
    (git_repo / "tracked.txt").write_text("base", encoding="utf-8")
    _git(git_repo, "add", "tracked.txt")
    _git(
        git_repo,
        "-c",
        "user.email=test@example.com",
        "-c",
        "user.name=test",
        "commit",
        "-q",
        "-m",
        "add tracked",
    )

    (git_repo / "staged.txt").write_text("staged", encoding="utf-8")
    _git(git_repo, "add", "staged.txt")

    (git_repo / "unstaged.txt").write_text("unstaged", encoding="utf-8")

    result = list_git_changed_files(git_repo, "staged")
    assert result == ["staged.txt"]


def test_relative_paths_from_subdirectory(git_repo: Path) -> None:
    sub = git_repo / "sub" / "dir"
    sub.mkdir(parents=True)
    (sub / "nested.txt").write_text("nested", encoding="utf-8")
    _git(git_repo, "add", "sub/dir/nested.txt")

    result = list_git_changed_files(sub, "staged")
    assert result == ["nested.txt"]


def test_filename_with_spaces_is_parsed(git_repo: Path) -> None:
    (git_repo / "file with spaces.txt").write_text("data", encoding="utf-8")
    _git(git_repo, "add", "file with spaces.txt")

    result = list_git_changed_files(git_repo, "staged")
    assert result == ["file with spaces.txt"]


def test_no_diff_raises_value_error(git_repo: Path) -> None:
    with pytest.raises(ValueError, match="git の差分が見つかりません"):
        list_git_changed_files(git_repo, "worktree")


def test_non_git_repository_raises_value_error(tmp_path: Path) -> None:
    not_repo = tmp_path / "plain_dir"
    not_repo.mkdir()
    with pytest.raises(ValueError, match="git リポジトリではありません"):
        list_git_changed_files(not_repo, "worktree")


def test_no_commits_raises_value_error(tmp_path: Path) -> None:
    repo = tmp_path / "unborn"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_text("a", encoding="utf-8")
    _git(repo, "add", "a.txt")

    # staged モードの `git diff --cached` は unborn HEAD でも空 tree と比較して
    # 成功するため、HEAD 欠落は worktree モード (`git diff ... HEAD`) で検証する。
    with pytest.raises(ValueError, match="HEAD が存在しません"):
        list_git_changed_files(repo, "worktree")


def test_git_binary_missing_raises_value_error(
    git_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_run(*_args: object, **_kwargs: object) -> None:
        raise FileNotFoundError

    monkeypatch.setattr("zipper.__main__.subprocess.run", fake_run)

    with pytest.raises(ValueError, match="git コマンドが見つかりません"):
        list_git_changed_files(git_repo, "worktree")


def test_staged_mode_content_is_from_working_tree(git_repo: Path) -> None:
    """既知のズレ: staged モードでも ZIP の内容は working tree のもの。"""
    (git_repo / "a.txt").write_text("staged content", encoding="utf-8")
    _git(git_repo, "add", "a.txt")
    (git_repo / "a.txt").write_text("unstaged edit", encoding="utf-8")

    files = list_git_changed_files(git_repo, "staged")
    zip_path = create_secure_encrypted_zip(
        git_repo, PASSWORD, git_repo.parent / "staged.zip", files=files
    )

    extract_dir = git_repo.parent / "extracted_staged"
    extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)
    assert (extract_dir / "a.txt").read_text() == "unstaged edit"


def test_git_add_f_includes_gitignored_file_via_files(git_repo: Path) -> None:
    """ディレクトリウォーク経路との契約差を固定する。

    `git add -f` された gitignore 対象は files 経路では含まれる。
    """
    (git_repo / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (git_repo / "ignored.txt").write_text("forced", encoding="utf-8")
    _git(git_repo, "add", "-f", "ignored.txt")

    files = list_git_changed_files(git_repo, "staged")
    assert files == ["ignored.txt"]

    zip_path = create_secure_encrypted_zip(
        git_repo, PASSWORD, git_repo.parent / "forced.zip", files=files
    )
    extract_dir = git_repo.parent / "extracted_forced"
    extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)
    assert (extract_dir / "ignored.txt").read_text() == "forced"


def test_create_extract_roundtrip_with_files(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "a.txt").write_text("A", encoding="utf-8")
    (root / "sub").mkdir()
    (root / "sub" / "b.txt").write_text("B", encoding="utf-8")
    (root / "excluded.txt").write_text("excluded", encoding="utf-8")

    zip_path = create_secure_encrypted_zip(
        root,
        PASSWORD,
        tmp_path / "files.zip",
        files=["a.txt", "sub/b.txt"],
    )

    extract_dir = tmp_path / "extracted_files"
    extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)

    assert (extract_dir / "a.txt").read_text() == "A"
    assert (extract_dir / "sub" / "b.txt").read_text() == "B"
    assert not (extract_dir / "excluded.txt").exists()


def test_create_rejects_empty_files_list(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "a.txt").write_text("A", encoding="utf-8")

    with pytest.raises(ValueError, match="files が空です"):
        create_secure_encrypted_zip(root, PASSWORD, tmp_path / "empty.zip", files=[])


def test_create_rejects_path_traversal_in_files(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "a.txt").write_text("A", encoding="utf-8")

    with pytest.raises(ValueError, match="'\\.\\.' を含むエントリ"):
        create_secure_encrypted_zip(
            root, PASSWORD, tmp_path / "escape.zip", files=["../escape"]
        )


def test_create_rejects_absolute_path_in_files(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "a.txt").write_text("A", encoding="utf-8")

    with pytest.raises(ValueError, match="絶対パスのエントリ"):
        create_secure_encrypted_zip(
            root, PASSWORD, tmp_path / "abs.zip", files=["/abs/path"]
        )


def test_create_rejects_files_when_target_is_file(tmp_path: Path) -> None:
    target_file = tmp_path / "single.txt"
    target_file.write_text("data", encoding="utf-8")

    with pytest.raises(ValueError, match="files 指定時に target をファイルにする"):
        create_secure_encrypted_zip(
            target_file, PASSWORD, tmp_path / "single.zip", files=["single.txt"]
        )


def test_create_rejects_missing_file_in_files_list(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "a.txt").write_text("A", encoding="utf-8")

    with pytest.raises(ValueError, match="ファイルが見つからないか"):
        create_secure_encrypted_zip(
            root, PASSWORD, tmp_path / "missing.zip", files=["a.txt", "missing.txt"]
        )


def test_create_rejects_directory_in_files_list(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "sub").mkdir()
    (root / "sub" / "b.txt").write_text("B", encoding="utf-8")

    with pytest.raises(ValueError, match="ファイルが見つからないか"):
        create_secure_encrypted_zip(
            root, PASSWORD, tmp_path / "dir_entry.zip", files=["sub"]
        )
