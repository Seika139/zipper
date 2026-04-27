import base64
import binascii
import json
import re
import shutil
from pathlib import Path
from zipfile import ZipFile

import pytest
from cryptography.fernet import Fernet

from zipper.core import (
    LEGACY_PBKDF2_ITERATIONS,
    create_secure_encrypted_zip,
    decrypt_file,
    decrypt_filename,
    encrypt_file,
    encrypt_filename,
    extract_secure_encrypted_zip,
    generate_key_from_password,
)

PASSWORD = b"test_password"


def test_generate_key_from_password() -> None:
    key, salt = generate_key_from_password(PASSWORD)
    assert isinstance(key, bytes)
    assert isinstance(salt, bytes)
    assert len(key) == 44
    assert len(salt) == 16


def test_encrypt_decrypt_file(tmp_path: Path) -> None:
    input_file = tmp_path / "test_file.txt"
    input_file.write_text("test data")
    encrypted_file = tmp_path / "test_file.txt.encrypted"
    salt, encrypted_bytes = encrypt_file(input_file, PASSWORD)
    encrypted_file.write_bytes(encrypted_bytes)
    decrypted_file = tmp_path / "test_file.txt.decrypted"
    decrypt_file(encrypted_file, decrypted_file, PASSWORD, salt)
    assert Path(decrypted_file).exists()
    assert decrypted_file.read_text() == "test data"


def test_create_extract_secure_encrypted_zip(tmp_path: Path) -> None:
    target_file = tmp_path / "test_file.txt"
    target_file.write_text("test data")
    zip_filename = tmp_path / "test_file_encrypted.zip"
    zip_filename = create_secure_encrypted_zip(target_file, PASSWORD, zip_filename)
    assert Path(zip_filename).exists()

    extract_dir = tmp_path / "extracted"
    extract_secure_encrypted_zip(zip_filename, PASSWORD, extract_dir)
    extracted_file = extract_dir / "test_file.txt"
    assert Path(extracted_file).exists()
    assert extracted_file.read_text() == "test data"


def test_create_extract_secure_encrypted_zip_directory(
    tmp_path: Path,
) -> None:
    target_dir = tmp_path / "test_dir"
    target_dir.mkdir()
    test_file = target_dir / "test_file.txt"
    test_file.write_text("test data")
    zip_filename = tmp_path / "test_dir_encrypted.zip"
    zip_filename = create_secure_encrypted_zip(target_dir, PASSWORD, zip_filename)
    assert Path(zip_filename).exists()

    extract_dir = tmp_path / "extracted"
    extract_secure_encrypted_zip(zip_filename, PASSWORD, extract_dir)
    extracted_file = extract_dir / "test_file.txt"
    assert Path(extracted_file).exists()
    assert extracted_file.read_text() == "test data"


def test_extract_secure_encrypted_zip_wrong_password(
    tmp_path: Path,
) -> None:
    target_file = tmp_path / "secret.txt"
    target_file.write_text("top secret")
    zip_path = create_secure_encrypted_zip(
        target_file, b"correct_password", tmp_path / "secret_encrypted.zip"
    )

    extract_dir = tmp_path / "extracted_wrong"
    extract_dir.mkdir(exist_ok=True)

    with pytest.raises(ValueError, match="パスワードが間違っています"):
        extract_secure_encrypted_zip(zip_path, b"wrong_password", extract_dir)

    assert not (extract_dir / "secret.txt").exists()


def test_create_secure_encrypted_zip_automatic_filename(
    tmp_path: Path,
) -> None:
    target_file = tmp_path / "data.txt"
    target_file.write_text("some data")
    zip_filename = create_secure_encrypted_zip(target_file, PASSWORD)
    assert zip_filename.name == "data_encrypted.zip"
    assert Path(zip_filename).exists()
    zip_filename.unlink()


def test_create_secure_encrypted_zip_invalid_target(
    tmp_path: Path,
) -> None:
    invalid_target = tmp_path / "non_existent_file"
    with pytest.raises(FileNotFoundError):
        create_secure_encrypted_zip(invalid_target, PASSWORD)


def test_secure_encrypted_zip_content(tmp_path: Path) -> None:
    target_file = tmp_path / "info.txt"
    target_file.write_text("important information")
    zip_filename = create_secure_encrypted_zip(
        target_file, PASSWORD, tmp_path / "info_encrypted.zip"
    )

    with ZipFile(zip_filename, "r") as zf:
        namelist = zf.namelist()
        assert "info.txt.salt" in namelist
        assert "info.txt.encrypted" in namelist


def test_create_encrypted_zip_with_gitignore(tmp_path: Path) -> None:
    test_dir = tmp_path / "project"
    test_dir.mkdir()

    gitignore_content = """
*.log
cache/
/dist/
/temp.*
/src/*.tmp
!*.py
"""
    (test_dir / ".gitignore").write_text(gitignore_content, encoding="utf-8")

    (test_dir / "main.py").write_text("print('Hello')", encoding="utf-8")
    (test_dir / "app.log").write_text("log content", encoding="utf-8")
    (test_dir / "temp.txt").write_text("temporary", encoding="utf-8")
    (test_dir / "temp.py").write_text("temporary py", encoding="utf-8")
    (test_dir / "cache").mkdir()
    (test_dir / "cache" / "data.txt").write_text("cache data", encoding="utf-8")
    (test_dir / "dist").mkdir()
    (test_dir / "dist" / "app.exe").write_text("binary", encoding="utf-8")
    (test_dir / "src").mkdir()
    (test_dir / "src" / "code.py").write_text("source code", encoding="utf-8")
    (test_dir / "src" / "temp.tmp").write_text("temporary", encoding="utf-8")
    (test_dir / "src" / "debug.log").write_text("debug info", encoding="utf-8")

    zip_output = test_dir.parent / "with_gitignore.zip"
    zip_path = create_secure_encrypted_zip(test_dir, PASSWORD, zip_output)
    assert zip_path.exists()

    extract_dir = test_dir.parent / "extracted_with_gitignore"
    extract_dir.mkdir()
    extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)

    assert (extract_dir / "main.py").exists()
    assert (extract_dir / "src" / "code.py").exists()
    assert not (extract_dir / "app.log").exists()
    assert not (extract_dir / "src" / "debug.log").exists()
    assert not (extract_dir / "temp.txt").exists()
    assert not (extract_dir / "cache").exists()
    assert not (extract_dir / "dist").exists()
    assert not (extract_dir / "src" / "temp.tmp").exists()
    assert (extract_dir / "temp.py").exists()


def test_create_encrypted_zip_without_gitignore(tmp_path: Path) -> None:
    test_dir = tmp_path / "project_no_ignore"
    test_dir.mkdir()

    (test_dir / "main.py").write_text("print('Hello')", encoding="utf-8")
    (test_dir / "app.log").write_text("log content", encoding="utf-8")
    (test_dir / "cache").mkdir()
    (test_dir / "cache" / "data.txt").write_text("cache data", encoding="utf-8")

    zip_output = test_dir.parent / "without_gitignore.zip"
    zip_path = create_secure_encrypted_zip(test_dir, PASSWORD, zip_output)
    assert zip_path.exists()

    extract_dir = test_dir.parent / "extracted_without_gitignore"
    extract_dir.mkdir()
    extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)

    assert (extract_dir / "main.py").exists()
    assert (extract_dir / "app.log").exists()
    assert (extract_dir / "cache" / "data.txt").exists()


def test_filename_encryption_decryption() -> None:
    key, _ = generate_key_from_password(PASSWORD)
    fernet = Fernet(key)

    original_name = "test_file.txt"
    encrypted_name = encrypt_filename(original_name, fernet)
    decrypted_name = decrypt_filename(encrypted_name, fernet)
    assert decrypted_name == original_name

    original_name_with_path = "dir1/subdir/test_file.txt"
    encrypted_name_with_path = encrypt_filename(original_name_with_path, fernet)
    decrypted_name_with_path = decrypt_filename(encrypted_name_with_path, fernet)
    assert decrypted_name_with_path == original_name_with_path

    original_name_jp = "テスト_ファイル.txt"
    encrypted_name_jp = encrypt_filename(original_name_jp, fernet)
    decrypted_name_jp = decrypt_filename(encrypted_name_jp, fernet)
    assert decrypted_name_jp == original_name_jp


def test_create_extract_with_filename_encryption(tmp_path: Path) -> None:
    test_dir = tmp_path / "test_dir"
    test_dir.mkdir()

    normal_file = test_dir / "test_file.txt"
    normal_file.write_text("test data")

    sub_dir = test_dir / "subdir"
    sub_dir.mkdir()
    sub_file = sub_dir / "sub_file.txt"
    sub_file.write_text("sub dir data")

    jp_file = test_dir / "テスト.txt"
    jp_file.write_text("日本語テスト")

    zip_filename = tmp_path / "encrypted.zip"
    zip_filename = create_secure_encrypted_zip(test_dir, PASSWORD, zip_filename)
    assert Path(zip_filename).exists()

    with ZipFile(zip_filename, "r") as zf:
        namelist = zf.namelist()
        assert "metadata.encrypted" in namelist
        for name in namelist:
            assert name.endswith((".encrypted", ".salt"))

    extract_dir = tmp_path / "extracted"
    extract_secure_encrypted_zip(zip_filename, PASSWORD, extract_dir)

    assert (extract_dir / "test_file.txt").exists()
    assert (extract_dir / "subdir" / "sub_file.txt").exists()
    assert (extract_dir / "テスト.txt").exists()
    assert (extract_dir / "test_file.txt").read_text() == "test data"
    assert (extract_dir / "subdir" / "sub_file.txt").read_text() == "sub dir data"
    assert (extract_dir / "テスト.txt").read_text() == "日本語テスト"


def test_create_extract_with_encrypted_filenames(tmp_path: Path) -> None:
    test_dir = tmp_path / "test_dir_encrypted_names"
    test_dir.mkdir()

    normal_file = test_dir / "secret_file.txt"
    normal_file.write_text("confidential data")

    sub_dir = test_dir / "private"
    sub_dir.mkdir()
    sub_file = sub_dir / "classified.txt"
    sub_file.write_text("top secret data")

    jp_file = test_dir / "機密情報.txt"
    jp_file.write_text("秘密のデータ")

    zip_filename = tmp_path / "encrypted_with_names.zip"
    zip_filename = create_secure_encrypted_zip(
        test_dir, PASSWORD, zip_filename, encrypt_filenames=True
    )
    assert Path(zip_filename).exists()

    with ZipFile(zip_filename, "r") as zf:
        namelist = zf.namelist()
        assert "metadata.encrypted" in namelist
        assert any(name.endswith("metadata.salt") for name in namelist)

        for name in namelist:
            if name == "metadata.encrypted" or name.endswith("metadata.salt"):
                continue
            assert name.endswith((".encrypted", ".salt"))
            name_without_ext = name.replace(".encrypted", "").replace(".salt", "")
            try:
                decoded = base64.urlsafe_b64decode(name_without_ext.encode("ascii"))
                assert b"secret_file.txt" not in decoded
                assert b"classified.txt" not in decoded
                assert "機密情報.txt".encode() not in decoded
            except (binascii.Error, ValueError):
                pytest.fail(f"Invalid base64 filename: {name_without_ext}")
            assert "secret_file.txt" not in name
            assert "classified.txt" not in name
            assert "機密情報.txt" not in name

    extract_dir = tmp_path / "extracted_with_encrypted_names"
    extract_dir.mkdir()
    extract_secure_encrypted_zip(zip_filename, PASSWORD, extract_dir)

    assert (extract_dir / "secret_file.txt").exists()
    assert (extract_dir / "private" / "classified.txt").exists()
    assert (extract_dir / "機密情報.txt").exists()
    assert (extract_dir / "secret_file.txt").read_text() == "confidential data"
    assert (extract_dir / "private" / "classified.txt").read_text() == "top secret data"
    assert (extract_dir / "機密情報.txt").read_text() == "秘密のデータ"


def test_filename_encryption_security() -> None:
    key, _ = generate_key_from_password(PASSWORD)
    fernet = Fernet(key)

    sensitive_names = [
        "password.txt",
        "credit_card_info.csv",
        "secret_key.pem",
        "機密情報.doc",
        "パスワード.txt",
        "private/sensitive_data.json",
    ]

    for original_name in sensitive_names:
        encrypted_name = encrypt_filename(original_name, fernet)

        assert original_name not in encrypted_name
        if "/" in original_name:
            assert "/" not in encrypted_name
        if "." in original_name:
            file_ext = original_name.split(".")[-1]
            assert file_ext not in encrypted_name

        try:
            decoded = base64.urlsafe_b64decode(encrypted_name.encode("ascii"))
            name_parts = re.split(r"[./]", original_name)
            for part in name_parts:
                if len(part) > 3:
                    assert part.encode("utf-8") not in decoded
        except (binascii.Error, ValueError):
            pytest.fail(f"Invalid base64 filename: {encrypted_name}")

        decrypted_name = decrypt_filename(encrypted_name, fernet)
        assert decrypted_name == original_name


def test_extract_non_encrypted_zip(tmp_path: Path) -> None:
    test_file = tmp_path / "normal.txt"
    test_file.write_text("normal content")
    normal_zip = tmp_path / "normal.zip"

    with ZipFile(normal_zip, "w") as zf:
        zf.write(test_file, test_file.name)

    extract_dir = tmp_path / "extracted_normal"
    extract_dir.mkdir()

    with pytest.raises(ValueError, match="は暗号化ZIPファイルではありません"):
        extract_secure_encrypted_zip(normal_zip, PASSWORD, extract_dir)

    assert not any(extract_dir.iterdir())


def test_extract_with_existing_files(tmp_path: Path) -> None:
    source_file = tmp_path / "secret.txt"
    source_file.write_text("secret content")
    zip_path = create_secure_encrypted_zip(
        source_file, PASSWORD, tmp_path / "secret_encrypted.zip"
    )

    extract_dir = tmp_path / "extract_with_existing"
    extract_dir.mkdir()
    existing_file = extract_dir / "existing.txt"
    existing_file.write_text("existing content")

    extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)

    assert existing_file.exists()
    assert existing_file.read_text() == "existing content"

    decrypted_file = extract_dir / "secret.txt"
    assert decrypted_file.exists()
    assert decrypted_file.read_text() == "secret content"


def test_zip_with_relative_path(tmp_path: Path) -> None:
    sub_dir = tmp_path / "subdir"
    sub_dir.mkdir()
    source_file = sub_dir / "data.txt"
    source_file.write_text("test data")

    relative_zip = Path("output.zip")
    zip_path = create_secure_encrypted_zip(source_file, PASSWORD, relative_zip)

    assert zip_path.parent == source_file.parent
    assert zip_path.exists()

    extract_dir = tmp_path / "extracted_relative"
    extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)
    decrypted_file = extract_dir / "data.txt"
    assert decrypted_file.exists()
    assert decrypted_file.read_text() == "test data"


def test_create_encrypted_zip_excludes_git_directory(
    tmp_path: Path,
) -> None:
    test_dir = tmp_path / "repo_with_git"
    test_dir.mkdir()
    (test_dir / "file.txt").write_text("content")

    git_dir = test_dir / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("git config")

    sub_dir = test_dir / "subdir"
    sub_dir.mkdir()
    (sub_dir / ".git").mkdir()
    (sub_dir / ".git" / "HEAD").write_text("ref: refs/heads/main")

    zip_output = tmp_path / "repo.zip"
    create_secure_encrypted_zip(test_dir, PASSWORD, zip_output)

    extract_dir = tmp_path / "extracted_repo"
    extract_secure_encrypted_zip(zip_output, PASSWORD, extract_dir)

    assert (extract_dir / "file.txt").exists()
    assert not (extract_dir / ".git").exists()
    assert not (extract_dir / "subdir" / ".git").exists()


def test_nested_gitignore_precedence(tmp_path: Path) -> None:
    root = tmp_path / "nested_ignore_test"
    root.mkdir()

    (root / ".gitignore").write_text("*.log\n")
    (root / "root.log").write_text("should be ignored")
    (root / "root.txt").write_text("should be kept")

    dir_a = root / "dir_a"
    dir_a.mkdir()
    (dir_a / ".gitignore").write_text("ignore_me.txt\n")
    (dir_a / "ignore_me.txt").write_text("should be ignored in A")
    (dir_a / "keep_me.txt").write_text("should be kept in A")
    (dir_a / "sub.log").write_text("should be ignored by root rule")

    dir_b = root / "dir_b"
    dir_b.mkdir()
    (dir_b / ".gitignore").write_text("!important.log\n")
    (dir_b / "important.log").write_text("should be kept despite root *.log")
    (dir_b / "other.log").write_text("should still be ignored")

    zip_output = tmp_path / "nested.zip"
    create_secure_encrypted_zip(root, PASSWORD, zip_output)

    extract_dir = tmp_path / "extracted_nested"
    extract_secure_encrypted_zip(zip_output, PASSWORD, extract_dir)

    assert (extract_dir / "root.txt").exists()
    assert not (extract_dir / "root.log").exists()
    assert (extract_dir / "dir_a" / "keep_me.txt").exists()
    assert not (extract_dir / "dir_a" / "ignore_me.txt").exists()
    assert not (extract_dir / "dir_a" / "sub.log").exists()
    assert (extract_dir / "dir_b" / "important.log").exists()
    assert not (extract_dir / "dir_b" / "other.log").exists()


def test_gitignore_negation_and_gitkeep(tmp_path: Path) -> None:
    root = tmp_path / "sample_ignore"
    root.mkdir()

    (root / ".gitignore").write_text(
        ".cache\nenvs/*\n!envs/.gitkeep\n", encoding="utf-8"
    )

    (root / "sample.py").write_text("print('ok')", encoding="utf-8")
    envs = root / "envs"
    envs.mkdir()
    (envs / ".gitkeep").write_text("", encoding="utf-8")
    (envs / "secret.env").write_text("SECRET=1", encoding="utf-8")

    secrets = root / "secrets"
    secrets.mkdir()
    (secrets / ".gitignore").write_text("!.gitkeep\n*.txt\n", encoding="utf-8")
    (secrets / ".gitkeep").write_text("", encoding="utf-8")
    (secrets / "secret.txt").write_text("top secret", encoding="utf-8")

    cache_dir = root / ".cache"
    cache_dir.mkdir()
    (cache_dir / "cache.txt").write_text("cached", encoding="utf-8")
    sub = root / "sub"
    sub.mkdir()
    (sub / ".cache").write_text("cached file", encoding="utf-8")

    zip_path = tmp_path / "sample_ignore.zip"
    create_secure_encrypted_zip(root, PASSWORD, zip_path)

    extract_dir = tmp_path / "extracted_sample_ignore"
    extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)

    assert (extract_dir / "sample.py").exists()
    assert (extract_dir / "envs" / ".gitkeep").exists()
    assert not (extract_dir / "envs" / "secret.env").exists()
    assert (extract_dir / "secrets" / ".gitkeep").exists()
    assert not (extract_dir / "secrets" / "secret.txt").exists()
    assert not (extract_dir / ".cache").exists()
    assert not (extract_dir / "sub" / ".cache").exists()


def test_gitignore_cache_excludes_directory_and_file(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cache_test"
    root.mkdir()
    (root / ".gitignore").write_text(".cache\n", encoding="utf-8")

    (root / "keep.txt").write_text("keep", encoding="utf-8")

    cache_dir = root / ".cache"
    cache_dir.mkdir()
    (cache_dir / "data.txt").write_text("cache dir content", encoding="utf-8")

    sub = root / "sub"
    sub.mkdir()
    (sub / ".cache").write_text("cache file", encoding="utf-8")

    zip_path = tmp_path / "cache_test.zip"
    create_secure_encrypted_zip(root, PASSWORD, zip_path)

    extract_dir = tmp_path / "extracted_cache_test"
    extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)

    assert (extract_dir / "keep.txt").exists()
    assert not (extract_dir / ".cache").exists()
    assert not (extract_dir / "sub" / ".cache").exists()


def test_extract_corrupt_metadata(tmp_path: Path) -> None:
    src = tmp_path / "src.txt"
    src.write_text("secret", encoding="utf-8")
    zip_path = tmp_path / "corrupt_meta.zip"
    create_secure_encrypted_zip(src, PASSWORD, zip_path)

    rebuilt = tmp_path / "corrupt_meta_rebuilt.zip"
    with ZipFile(zip_path, "r") as src_zip, ZipFile(rebuilt, "w") as dst_zip:
        for info in src_zip.infolist():
            if info.filename == "metadata.encrypted":
                continue
            dst_zip.writestr(info, src_zip.read(info.filename))
        dst_zip.writestr("metadata.encrypted", b"corrupted")
    rebuilt.replace(zip_path)

    extract_dir = tmp_path / "extract_corrupt_meta"
    with pytest.raises(ValueError, match="パスワードが間違っています"):
        extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)
    assert not extract_dir.exists()


def test_extract_missing_metadata_salt(tmp_path: Path) -> None:
    src = tmp_path / "src.txt"
    src.write_text("secret", encoding="utf-8")
    zip_path = tmp_path / "missing_salt.zip"
    create_secure_encrypted_zip(src, PASSWORD, zip_path)

    rebuilt = tmp_path / "missing_salt_rebuilt.zip"
    with ZipFile(zip_path, "r") as src_zip, ZipFile(rebuilt, "w") as dst_zip:
        for info in src_zip.infolist():
            if info.filename.endswith("metadata.salt"):
                continue
            dst_zip.writestr(info, src_zip.read(info.filename))
    rebuilt.rename(zip_path)

    extract_dir = tmp_path / "extract_missing_salt"
    with pytest.raises(ValueError, match=r"metadata.saltが見つかりません"):
        extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)
    assert not extract_dir.exists()


def test_extract_corrupt_file_salt_triggers_cleanup(
    tmp_path: Path,
) -> None:
    root = tmp_path / "multi"
    root.mkdir()
    (root / "a.txt").write_text("A", encoding="utf-8")
    (root / "b.txt").write_text("B", encoding="utf-8")
    zip_path = tmp_path / "multi.zip"
    create_secure_encrypted_zip(root, PASSWORD, zip_path)

    rebuilt = tmp_path / "multi_rebuilt.zip"
    with ZipFile(zip_path, "r") as src_zip, ZipFile(rebuilt, "w") as dst_zip:
        salt_name = next(n for n in src_zip.namelist() if n.endswith("b.txt.salt"))
        for info in src_zip.infolist():
            if info.filename == salt_name:
                continue
            dst_zip.writestr(info, src_zip.read(info.filename))
        dst_zip.writestr(salt_name, b"bad_salt")
    rebuilt.replace(zip_path)

    extract_dir = tmp_path / "extract_multi"
    with pytest.raises(ValueError, match="パスワードが間違っています"):
        extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)
    assert not extract_dir.exists()


def test_extract_handles_windows_style_paths(tmp_path: Path) -> None:
    root = tmp_path / "paths"
    root.mkdir()
    (root / "dir" / "sub").mkdir(parents=True)
    (root / "dir" / "sub" / "file.txt").write_text("data", encoding="utf-8")
    zip_path = tmp_path / "paths.zip"
    create_secure_encrypted_zip(root, PASSWORD, zip_path)

    with ZipFile(zip_path, "r") as zf:
        metadata_salt_name = next(
            n for n in zf.namelist() if n.endswith("metadata.salt")
        )
        metadata_salt = zf.read(metadata_salt_name)
        encrypted_metadata = zf.read("metadata.encrypted")

    key, _ = generate_key_from_password(PASSWORD, metadata_salt)
    fernet = Fernet(key)
    metadata = json.loads(fernet.decrypt(encrypted_metadata).decode("utf-8"))
    metadata["file_mapping"] = {
        k.replace("/", "\\"): v for k, v in metadata["file_mapping"].items()
    }
    new_encrypted_metadata = fernet.encrypt(
        json.dumps(metadata, ensure_ascii=False).encode("utf-8")
    )

    rebuilt = tmp_path / "paths_rebuilt.zip"
    with ZipFile(zip_path, "r") as src_zip, ZipFile(rebuilt, "w") as dst_zip:
        for info in src_zip.infolist():
            if info.filename == "metadata.encrypted":
                continue
            dst_zip.writestr(info, src_zip.read(info.filename))
        dst_zip.writestr("metadata.encrypted", new_encrypted_metadata)
    rebuilt.replace(zip_path)

    extract_dir = tmp_path / "extract_paths"
    extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)
    assert (extract_dir / "dir" / "sub" / "file.txt").exists()
    assert (extract_dir / "dir" / "sub" / "file.txt").read_text() == "data"


def test_gitignore_ignores_empty_directory(tmp_path: Path) -> None:
    root = tmp_path / "empty_ignore"
    root.mkdir()
    ignored = root / "ignored_dir"
    ignored.mkdir()
    (ignored / ".gitignore").write_text("*\n", encoding="utf-8")

    zip_path = tmp_path / "empty_ignore.zip"
    create_secure_encrypted_zip(root, PASSWORD, zip_path)

    extract_dir = tmp_path / "extract_empty_ignore"
    extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)

    assert not (extract_dir / "ignored_dir").exists()


def test_auto_zip_filename_collision(tmp_path: Path) -> None:
    target = tmp_path / "collision.txt"
    target.write_text("x", encoding="utf-8")

    first = create_secure_encrypted_zip(target, PASSWORD)
    second = create_secure_encrypted_zip(target, PASSWORD)

    assert first.name == "collision_encrypted.zip"
    assert second.name == "collision_encrypted_1.zip"


def test_gitignore_case_sensitive(tmp_path: Path) -> None:
    case_check = tmp_path / "CaseCheck"
    case_check.touch()
    is_case_insensitive = (tmp_path / "casecheck").exists()
    case_check.unlink()
    if is_case_insensitive:
        pytest.skip("このテストには大文字小文字を区別するファイルシステムが必要です。")

    root = tmp_path / "case"
    root.mkdir()
    (root / ".gitignore").write_text("*.log\n", encoding="utf-8")
    (root / "app.log").write_text("lower", encoding="utf-8")
    (root / "APP.LOG").write_text("upper", encoding="utf-8")

    zip_path = tmp_path / "case.zip"
    create_secure_encrypted_zip(root, PASSWORD, zip_path)
    extract_dir = tmp_path / "extract_case"
    extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)

    assert not (extract_dir / "app.log").exists()
    assert (extract_dir / "APP.LOG").exists()


def test_wrong_password_does_not_remove_existing_dir(
    tmp_path: Path,
) -> None:
    src = tmp_path / "keep.txt"
    src.write_text("keep", encoding="utf-8")
    zip_path = tmp_path / "keep.zip"
    create_secure_encrypted_zip(src, b"correct", zip_path)

    extract_dir = tmp_path / "existing_extract"
    extract_dir.mkdir()
    existing_file = extract_dir / "existing.txt"
    existing_file.write_text("existing", encoding="utf-8")

    with pytest.raises(ValueError, match="パスワードが間違っています"):
        extract_secure_encrypted_zip(zip_path, b"wrong", extract_dir)

    assert extract_dir.exists()
    assert existing_file.exists()
    assert existing_file.read_text() == "existing"


def test_metadata_records_version_and_iterations(tmp_path: Path) -> None:
    src = tmp_path / "probe.txt"
    src.write_text("probe", encoding="utf-8")
    zip_path = create_secure_encrypted_zip(src, PASSWORD, tmp_path / "probe.zip")

    with ZipFile(zip_path, "r") as zf:
        metadata_salt = zf.read(
            next(n for n in zf.namelist() if n.endswith("metadata.salt"))
        )
        encrypted_metadata = zf.read("metadata.encrypted")

    key, _ = generate_key_from_password(PASSWORD, metadata_salt)
    metadata = json.loads(Fernet(key).decrypt(encrypted_metadata).decode("utf-8"))
    assert metadata["version"] >= 2
    assert metadata["kdf"]["algorithm"] == "pbkdf2-sha256"
    assert metadata["kdf"]["iterations"] == 600_000


def test_extract_legacy_metadata_without_version(tmp_path: Path) -> None:
    """旧 0.1.0 製 ZIP (version/kdf なし、iterations=390,000) を復号できる。"""
    src = tmp_path / "legacy.txt"
    src.write_text("legacy payload", encoding="utf-8")
    zip_path = create_secure_encrypted_zip(src, PASSWORD, tmp_path / "legacy.zip")

    with ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        metadata_salt_name = next(n for n in names if n.endswith("metadata.salt"))
        metadata_salt = zf.read(metadata_salt_name)
        infos = {info.filename: info for info in zf.infolist()}
        payloads = {
            name: zf.read(name) for name in names if name != "metadata.encrypted"
        }

    legacy_key, _ = generate_key_from_password(
        PASSWORD, metadata_salt, LEGACY_PBKDF2_ITERATIONS
    )
    legacy_metadata = {
        "file_mapping": {"legacy.txt": "legacy.txt"},
        "encrypt_filenames": False,
    }
    legacy_encrypted = Fernet(legacy_key).encrypt(
        json.dumps(legacy_metadata, ensure_ascii=False).encode("utf-8")
    )

    legacy_file_salt = b"\x00" * 16
    legacy_file_key, _ = generate_key_from_password(
        PASSWORD, legacy_file_salt, LEGACY_PBKDF2_ITERATIONS
    )
    legacy_file_bytes = Fernet(legacy_file_key).encrypt(b"legacy payload")

    rebuilt = tmp_path / "legacy_rebuilt.zip"
    with ZipFile(rebuilt, "w") as dst:
        for name, data in payloads.items():
            if name in {"legacy.txt.salt", "legacy.txt.encrypted"}:
                continue
            dst.writestr(infos[name], data)
        dst.writestr("legacy.txt.salt", legacy_file_salt)
        dst.writestr("legacy.txt.encrypted", legacy_file_bytes)
        dst.writestr("metadata.encrypted", legacy_encrypted)
    rebuilt.replace(zip_path)

    extract_dir = tmp_path / "extract_legacy"
    extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)
    assert (extract_dir / "legacy.txt").read_text() == "legacy payload"


def test_extract_cleans_up_intermediate_directories(tmp_path: Path) -> None:
    """パスワード誤りの rollback で中間ディレクトリも消えることを検証する。"""
    root = tmp_path / "deep"
    root.mkdir()
    deep_file = root / "a" / "b" / "c" / "leaf.txt"
    deep_file.parent.mkdir(parents=True)
    deep_file.write_text("leaf", encoding="utf-8")

    zip_path = tmp_path / "deep.zip"
    create_secure_encrypted_zip(root, b"correct", zip_path)

    extract_dir = tmp_path / "extract_deep"
    with pytest.raises(ValueError, match="パスワードが間違っています"):
        extract_secure_encrypted_zip(zip_path, b"wrong", extract_dir)

    assert not extract_dir.exists()


def _tamper_file_mapping(
    zip_path: Path, password: bytes, new_mapping: dict[str, str]
) -> None:
    """ZIP 内のメタデータを書き換えて file_mapping を差し替える。

    攻撃面テスト用ヘルパ。
    """
    with ZipFile(zip_path, "r") as zf:
        metadata_salt = zf.read("metadata.salt")
        encrypted_metadata = zf.read("metadata.encrypted")
        infos = list(zf.infolist())
        payloads = {info.filename: zf.read(info.filename) for info in infos}

    key, _ = generate_key_from_password(password, metadata_salt)
    metadata = json.loads(Fernet(key).decrypt(encrypted_metadata).decode("utf-8"))
    metadata["file_mapping"] = new_mapping
    new_encrypted = Fernet(key).encrypt(
        json.dumps(metadata, ensure_ascii=False).encode("utf-8")
    )

    rebuilt = zip_path.with_suffix(".rebuilt.zip")
    with ZipFile(rebuilt, "w") as dst:
        for info in infos:
            if info.filename == "metadata.encrypted":
                dst.writestr(info, new_encrypted)
            else:
                dst.writestr(info, payloads[info.filename])
    rebuilt.replace(zip_path)


def test_rejects_path_traversal_escape(tmp_path: Path) -> None:
    """../ を使って extract_dir の外に書き出す攻撃を拒否する。"""
    src = tmp_path / "src.txt"
    src.write_text("data", encoding="utf-8")
    zip_path = tmp_path / "attack.zip"
    create_secure_encrypted_zip(src, PASSWORD, zip_path)

    _tamper_file_mapping(zip_path, PASSWORD, {"../escaped.txt": "src.txt"})

    extract_dir = tmp_path / "safe_extract"
    with pytest.raises(ValueError, match="'\\.\\.' を含むエントリ"):
        extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)

    assert not (tmp_path / "escaped.txt").exists()
    assert not extract_dir.exists()


def test_rejects_absolute_path_entry(tmp_path: Path) -> None:
    src = tmp_path / "src.txt"
    src.write_text("data", encoding="utf-8")
    zip_path = tmp_path / "absolute.zip"
    create_secure_encrypted_zip(src, PASSWORD, zip_path)

    _tamper_file_mapping(zip_path, PASSWORD, {"/tmp/evil.txt": "src.txt"})  # noqa: S108

    extract_dir = tmp_path / "absolute_extract"
    with pytest.raises(ValueError, match="絶対パスのエントリ"):
        extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)

    assert not Path("/tmp/evil.txt").exists()  # noqa: S108


def test_rejects_symlink_in_extract_path(tmp_path: Path) -> None:
    """途中コンポーネントが symlink の場合、リンク先への書き込みを拒否する。"""
    src = tmp_path / "src"
    src.mkdir()
    (src / "inner" / "file.txt").parent.mkdir()
    (src / "inner" / "file.txt").write_text("data", encoding="utf-8")
    zip_path = tmp_path / "symlink.zip"
    create_secure_encrypted_zip(src, PASSWORD, zip_path)

    extract_dir = tmp_path / "sym_extract"
    extract_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (extract_dir / "inner").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink を含むエントリ"):
        extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)

    assert not (outside / "file.txt").exists()


def test_rejects_reserved_filename_on_encrypt(tmp_path: Path) -> None:
    """ファイル名 'metadata' は metadata.salt/encrypted と衝突するので拒否する。"""
    src = tmp_path / "src"
    src.mkdir()
    (src / "metadata").write_text("oops", encoding="utf-8")

    with pytest.raises(ValueError, match="予約名と衝突"):
        create_secure_encrypted_zip(src, PASSWORD, tmp_path / "clash.zip")


def test_reserved_name_ok_with_encrypt_filenames(tmp_path: Path) -> None:
    """encrypt_filenames=True なら 'metadata' という名前も安全に暗号化できる。"""
    src = tmp_path / "src"
    src.mkdir()
    (src / "metadata").write_text("payload", encoding="utf-8")

    zip_path = create_secure_encrypted_zip(
        src, PASSWORD, tmp_path / "ok.zip", encrypt_filenames=True
    )
    extract_dir = tmp_path / "extract_ok"
    extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)

    assert (extract_dir / "metadata").read_text() == "payload"


def test_metadata_salt_lookup_is_exact_match(tmp_path: Path) -> None:
    """dir/metadata.salt があっても metadata.salt の探索が誤爆しない。

    encrypt_filenames=True で dir/metadata.salt を含む ZIP を作り、
    正しく復号できることを確認する。encrypt_filenames=False だと
    予約名衝突で作成時点で拒否されるため、ここでは True で検証する。
    """
    src = tmp_path / "src"
    (src / "dir").mkdir(parents=True)
    (src / "dir" / "metadata.salt").write_text("user data", encoding="utf-8")

    zip_path = create_secure_encrypted_zip(
        src, PASSWORD, tmp_path / "collide.zip", encrypt_filenames=True
    )
    extract_dir = tmp_path / "collide_extract"
    extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)

    assert (extract_dir / "dir" / "metadata.salt").read_text() == "user data"


def test_overwrite_existing_files_succeeds(tmp_path: Path) -> None:
    """既存ファイルを ZIP の同名ファイルで上書き解凍できる(成功パス)。"""
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("new A", encoding="utf-8")
    (src / "b.txt").write_text("new B", encoding="utf-8")
    zip_path = create_secure_encrypted_zip(src, PASSWORD, tmp_path / "src.zip")

    target = tmp_path / "target"
    target.mkdir()
    (target / "a.txt").write_text("old A", encoding="utf-8")
    (target / "b.txt").write_text("old B", encoding="utf-8")
    (target / "untouched.txt").write_text("KEEP", encoding="utf-8")

    extract_secure_encrypted_zip(zip_path, PASSWORD, target)

    assert (target / "a.txt").read_text() == "new A"
    assert (target / "b.txt").read_text() == "new B"
    assert (target / "untouched.txt").read_text() == "KEEP"


def test_rollback_restores_overwritten_files_on_corrupt_entry(
    tmp_path: Path,
) -> None:
    """途中の復号失敗で、既に上書き対象だった既存ファイルが完全復元される。"""
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("ZIP A", encoding="utf-8")
    (src / "b.txt").write_text("ZIP B", encoding="utf-8")
    zip_path = create_secure_encrypted_zip(src, PASSWORD, tmp_path / "src.zip")

    rebuilt = tmp_path / "src_corrupt.zip"
    with ZipFile(zip_path, "r") as src_zip, ZipFile(rebuilt, "w") as dst_zip:
        salt_name = next(n for n in src_zip.namelist() if n.endswith("b.txt.salt"))
        for info in src_zip.infolist():
            if info.filename == salt_name:
                continue
            dst_zip.writestr(info, src_zip.read(info.filename))
        dst_zip.writestr(salt_name, b"bad_salt")
    rebuilt.replace(zip_path)

    target = tmp_path / "target"
    target.mkdir()
    (target / "a.txt").write_text("ORIGINAL A", encoding="utf-8")
    (target / "b.txt").write_text("ORIGINAL B", encoding="utf-8")
    (target / "untouched.txt").write_text("KEEP", encoding="utf-8")

    with pytest.raises(ValueError, match="パスワードが間違っています"):
        extract_secure_encrypted_zip(zip_path, PASSWORD, target)

    assert (target / "a.txt").read_text() == "ORIGINAL A"
    assert (target / "b.txt").read_text() == "ORIGINAL B"
    assert (target / "untouched.txt").read_text() == "KEEP"


def test_rollback_restores_existing_files_on_symlink_error(
    tmp_path: Path,
) -> None:
    """extract_dir に symlink がある場合、Phase 0 で abort し既存ファイルは無傷。"""
    src = tmp_path / "src"
    src.mkdir()
    (src / "inner").mkdir()
    (src / "inner" / "file.txt").write_text("from zip", encoding="utf-8")
    (src / "top.txt").write_text("zip top", encoding="utf-8")
    zip_path = create_secure_encrypted_zip(src, PASSWORD, tmp_path / "src.zip")

    target = tmp_path / "target"
    target.mkdir()
    (target / "top.txt").write_text("ORIGINAL TOP", encoding="utf-8")
    (target / "untouched.txt").write_text("KEEP", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (target / "inner").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink を含むエントリ"):
        extract_secure_encrypted_zip(zip_path, PASSWORD, target)

    assert (target / "top.txt").read_text() == "ORIGINAL TOP"
    assert (target / "untouched.txt").read_text() == "KEEP"
    assert (target / "inner").is_symlink()
    assert not (outside / "file.txt").exists()


def test_rollback_leaves_no_staging_or_backup_directories(
    tmp_path: Path,
) -> None:
    """エラー rollback 後、staging/backup の作業 dir が一切残らない。"""
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("A", encoding="utf-8")
    zip_path = create_secure_encrypted_zip(src, PASSWORD, tmp_path / "src.zip")

    target = tmp_path / "target"
    target.mkdir()
    (target / "a.txt").write_text("ORIGINAL", encoding="utf-8")

    with pytest.raises(ValueError, match="パスワードが間違っています"):
        extract_secure_encrypted_zip(zip_path, b"wrong", target)

    assert (target / "a.txt").read_text() == "ORIGINAL"
    leftovers = [
        p for p in target.parent.iterdir() if p.name.startswith(".target.zipper-")
    ]
    assert leftovers == []


def test_success_leaves_no_staging_or_backup_directories(
    tmp_path: Path,
) -> None:
    """成功時にも staging/backup の作業 dir が一切残らない。"""
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("A", encoding="utf-8")
    (src / "b.txt").write_text("B", encoding="utf-8")
    zip_path = create_secure_encrypted_zip(src, PASSWORD, tmp_path / "src.zip")

    target = tmp_path / "target"
    target.mkdir()
    (target / "a.txt").write_text("OLD A", encoding="utf-8")

    extract_secure_encrypted_zip(zip_path, PASSWORD, target)

    leftovers = [
        p for p in target.parent.iterdir() if p.name.startswith(".target.zipper-")
    ]
    assert leftovers == []
    assert (target / "a.txt").read_text() == "A"
    assert (target / "b.txt").read_text() == "B"


def test_cleanup_failure_does_not_trigger_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """成功 commit 後の cleanup 失敗で配置済みファイルが消えないことを検証する。

    成功時の作業 dir 撤去 (`shutil.rmtree`) が何らかの理由で失敗した場合に、
    例外が `try` を抜けて rollback 経路に入ると、commit 完了済みのユーザー
    データを破壊しかねない。`finally` + `ignore_errors=True` で封じる。
    """
    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("ZIP A", encoding="utf-8")
    (src / "b.txt").write_text("ZIP B", encoding="utf-8")
    zip_path = create_secure_encrypted_zip(src, PASSWORD, tmp_path / "src.zip")

    target = tmp_path / "target"
    target.mkdir()
    (target / "a.txt").write_text("OLD A", encoding="utf-8")

    real_rmtree = shutil.rmtree

    def flaky_rmtree(path: str | Path, ignore_errors: bool = False) -> None:
        if "zipper-staging-" in str(path) and not ignore_errors:
            msg = "simulated rmtree failure"
            raise OSError(msg)
        real_rmtree(path, ignore_errors=ignore_errors)

    monkeypatch.setattr("zipper.core.shutil.rmtree", flaky_rmtree)

    extract_secure_encrypted_zip(zip_path, PASSWORD, target)

    assert (target / "a.txt").read_text() == "ZIP A"
    assert (target / "b.txt").read_text() == "ZIP B"


def test_rollback_after_path_traversal_preserves_existing_files(
    tmp_path: Path,
) -> None:
    """悪意のある file_mapping で abort 時、既存 dir 内の他ファイルは保護される。"""
    src = tmp_path / "src"
    src.mkdir()
    (src / "good.txt").write_text("good", encoding="utf-8")
    zip_path = create_secure_encrypted_zip(src, PASSWORD, tmp_path / "src.zip")
    _tamper_file_mapping(
        zip_path, PASSWORD, {"good.txt": "good.txt", "../escape.txt": "good.txt"}
    )

    target = tmp_path / "target"
    target.mkdir()
    (target / "keep.txt").write_text("keep", encoding="utf-8")

    with pytest.raises(ValueError, match="'\\.\\.' を含むエントリ"):
        extract_secure_encrypted_zip(zip_path, PASSWORD, target)

    assert (target / "keep.txt").read_text() == "keep"
    assert not (target / "good.txt").exists()
    assert not (tmp_path / "escape.txt").exists()


def test_rejects_bogus_iterations_in_metadata(tmp_path: Path) -> None:
    """メタデータの kdf.iterations が未許可値なら拒否する。"""
    src = tmp_path / "src.txt"
    src.write_text("data", encoding="utf-8")
    zip_path = tmp_path / "bad_iter.zip"
    create_secure_encrypted_zip(src, PASSWORD, zip_path)

    with ZipFile(zip_path, "r") as zf:
        metadata_salt = zf.read("metadata.salt")
        encrypted_metadata = zf.read("metadata.encrypted")
        infos = list(zf.infolist())
        payloads = {info.filename: zf.read(info.filename) for info in infos}

    key, _ = generate_key_from_password(PASSWORD, metadata_salt)
    metadata = json.loads(Fernet(key).decrypt(encrypted_metadata).decode("utf-8"))
    metadata["kdf"]["iterations"] = 10_000_000_000
    tampered = Fernet(key).encrypt(
        json.dumps(metadata, ensure_ascii=False).encode("utf-8")
    )

    rebuilt = tmp_path / "rebuilt.zip"
    with ZipFile(rebuilt, "w") as dst:
        for info in infos:
            if info.filename == "metadata.encrypted":
                dst.writestr(info, tampered)
            else:
                dst.writestr(info, payloads[info.filename])
    rebuilt.replace(zip_path)

    extract_dir = tmp_path / "bad_iter_extract"
    with pytest.raises(ValueError, match=r"未対応の kdf\.iterations"):
        extract_secure_encrypted_zip(zip_path, PASSWORD, extract_dir)
