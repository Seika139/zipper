import base64
import contextlib
import json
import logging
import os
import shutil
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

import pathspec
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

DEFAULT_PBKDF2_ITERATIONS = 600_000
LEGACY_PBKDF2_ITERATIONS = 390_000
ALLOWED_PBKDF2_ITERATIONS = frozenset({
    LEGACY_PBKDF2_ITERATIONS,
    DEFAULT_PBKDF2_ITERATIONS,
})
METADATA_VERSION = 2
METADATA_ENCRYPTED_NAME = "metadata.encrypted"
METADATA_SALT_NAME = "metadata.salt"
RESERVED_NAMES = frozenset({METADATA_ENCRYPTED_NAME, METADATA_SALT_NAME})


def _safe_join(base: Path, entry_path: str) -> Path:
    """ZIP エントリの相対パスを extract_dir 配下へ安全に結合する。

    Zip Slip 攻撃を防ぐため、以下を拒否する:
    - 絶対パス (POSIX の `/`, Windows のドライブ文字)
    - `..` を含むパス
    - 途中コンポーネントの symlink

    Returns:
        extract_dir 配下の解決済み絶対パス

    Raises:
        ValueError: 不正なエントリパスを検出した場合
    """
    normalized = entry_path.replace("\\", "/")
    rel = PurePosixPath(normalized)

    if rel.is_absolute() or rel.drive:
        msg = f"絶対パスのエントリは許可されていません: {entry_path}"
        raise ValueError(msg)
    if any(part == ".." for part in rel.parts):
        msg = f"'..' を含むエントリは許可されていません: {entry_path}"
        raise ValueError(msg)
    if not rel.parts:
        msg = f"空のエントリパスは許可されていません: {entry_path}"
        raise ValueError(msg)

    base_resolved = base.resolve()
    candidate = base_resolved.joinpath(*rel.parts)

    probe = candidate.parent
    while probe not in {base_resolved, probe.parent}:
        if probe.is_symlink():
            msg = f"symlink を含むエントリは許可されていません: {entry_path}"
            raise ValueError(msg)
        probe = probe.parent

    resolved = candidate.resolve() if candidate.exists() else candidate
    try:
        resolved.relative_to(base_resolved)
    except ValueError as e:
        msg = f"extract_dir 外への書き込みを検出: {entry_path}"
        raise ValueError(msg) from e

    return candidate


def generate_key_from_password(
    password: bytes,
    salt: bytes | None = None,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
) -> tuple[bytes, bytes]:
    """パスワードとソルトから暗号化キーを生成する。

    Args:
        password: パスワードのバイト列
        salt: ソルトのバイト列(省略可能)
        iterations: PBKDF2 の反復回数

    Returns:
        tuple[bytes, bytes]: 生成されたキーとソルト
    """
    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key, salt


def encrypt_file(
    input_path: Path,
    password: bytes,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
) -> tuple[bytes, bytes]:
    """ファイルを暗号化し、暗号化済みデータとソルトを返す。

    Returns:
        tuple[bytes, bytes]: (salt, encrypted_data)
    """
    salt = os.urandom(16)
    key, _ = generate_key_from_password(password, salt, iterations)
    f = Fernet(key)
    data = Path(input_path).read_bytes()
    encrypted_data = f.encrypt(data)
    return salt, encrypted_data


def decrypt_file(
    input_path: Path,
    output_path: Path,
    password: bytes,
    salt: bytes,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
) -> None:
    """暗号化されたファイルを復号化する。"""
    key, _ = generate_key_from_password(password, salt, iterations)
    f = Fernet(key)
    encrypted_data = Path(input_path).read_bytes()
    decrypted_data = f.decrypt(encrypted_data)
    Path(output_path).write_bytes(decrypted_data)


def load_gitignore_patterns(
    directory: Path,
) -> list[tuple[Path, Any]]:
    """指定ディレクトリの .gitignore を pathspec パターンに変換する。

    Returns:
        list[tuple[Path, Any]]: (ベースディレクトリ, パターン) のリスト。
    """
    gitignore_path = directory / ".gitignore"
    if not gitignore_path.is_file():
        return []

    patterns: list[tuple[Path, Any]] = []
    with Path(gitignore_path).open(encoding="utf-8") as f:
        spec = pathspec.PathSpec.from_lines("gitignore", f)
        patterns.extend((directory, p) for p in spec.patterns)
    return patterns


def is_ignored_by_gitignore(path: Path, patterns: list[tuple[Path, Any]]) -> bool:
    """.gitignore の評価順に従い、最後にマッチしたルールで判定する。

    Returns:
        bool: True なら除外対象。
    """
    ignored = False
    for base_dir, pattern in patterns:
        try:
            relative_path = path.relative_to(base_dir).as_posix()
        except ValueError:
            continue

        candidates = [relative_path]
        if path.is_dir():
            candidates.append(f"{relative_path}/")

        if any(pattern.match_file(candidate) for candidate in candidates):
            ignored = bool(pattern.include)
    return ignored


def encrypt_filename(filename: str, fernet: Fernet) -> str:
    """ファイル名を暗号化する。

    Returns:
        str: 暗号化されたファイル名(Fernetトークン)

    Raises:
        ValueError: 暗号化に失敗した場合
    """
    try:
        encrypted_bytes = fernet.encrypt(filename.encode("utf-8"))
        encrypted_name = encrypted_bytes.decode("ascii")
    except Exception as e:
        msg = f"ファイル名の暗号化に失敗しました: {filename} ({e!s})"
        raise ValueError(msg) from e
    return encrypted_name


def decrypt_filename(encrypted_filename: str, fernet: Fernet) -> str:
    """暗号化されたファイル名を復号化する。

    Returns:
        str: 復号化されたファイル名

    Raises:
        ValueError: 復号化に失敗した場合
    """
    try:
        logger.debug("復号化前のファイル名: %s", encrypted_filename)
        decrypted_bytes = fernet.decrypt(encrypted_filename.encode("ascii"))
        decrypted_name = decrypted_bytes.decode("utf-8")
        logger.debug("復号化後のファイル名: %s", decrypted_name)
    except Exception as e:
        msg = f"ファイル名の復号化に失敗しました: {encrypted_filename} ({e!s})"
        raise ValueError(msg) from e
    return decrypted_name


def _resolve_zip_filename(target: Path, zip_filename: Path | None) -> Path:
    """ZIP出力先パスを確定する。未指定時は自動命名+連番で衝突回避。

    Returns:
        Path: 出力先ZIPファイルのパス
    """
    if zip_filename is not None:
        if not zip_filename.is_absolute():
            zip_filename = target.parent / zip_filename
        return zip_filename.resolve()

    if target.is_file():
        base = target.stem + "_encrypted"
    else:
        base = target.name + "_encrypted"
    parent = target.parent
    suffix = ".zip"

    result = parent / f"{base}{suffix}"
    counter = 1
    while result.exists():
        result = parent / f"{base}_{counter}{suffix}"
        counter += 1
    return result


def create_secure_encrypted_zip(
    target: Path,
    password: bytes,
    zip_filename: Path | None = None,
    encrypt_filenames: bool = False,
) -> Path:
    """指定されたファイルやディレクトリを暗号化してZIPを作成する。

    Args:
        target: 圧縮対象のファイルまたはディレクトリのパス
        password: 暗号化パスワード
        zip_filename: 出力するZIPファイルのパス(省略可能)
        encrypt_filenames: ファイル名を暗号化するかどうか

    Returns:
        作成されたZIPファイルのパス

    Raises:
        FileNotFoundError: 指定されたパスが存在しない場合
        ValueError: パスの種類が不正な場合
    """
    if not target.exists():
        msg = f"指定されたパス '{target}' が見つかりません。"
        raise FileNotFoundError(msg)

    target = target.resolve()
    zip_filename = _resolve_zip_filename(target, zip_filename)

    iterations = DEFAULT_PBKDF2_ITERATIONS
    metadata_salt = os.urandom(16)
    metadata_key, _ = generate_key_from_password(password, metadata_salt, iterations)
    metadata_fernet = Fernet(metadata_key)
    file_mapping: dict[str, str] = {}

    def _add_file(zf: zipfile.ZipFile, file_path: Path, relative_path: str) -> None:
        logger.info("📩 圧縮: %s", relative_path)
        if encrypt_filenames:
            name = encrypt_filename(relative_path, metadata_fernet)
        else:
            name = relative_path
        salt_entry = f"{name}.salt"
        encrypted_entry = f"{name}.encrypted"
        if salt_entry in RESERVED_NAMES or encrypted_entry in RESERVED_NAMES:
            msg = (
                f"予約名と衝突するファイル名は暗号化できません: {relative_path} "
                "(encrypt_filenames=True で回避してください)"
            )
            raise ValueError(msg)
        file_mapping[relative_path] = name
        salt, encrypted_bytes = encrypt_file(file_path, password, iterations)
        zf.writestr(salt_entry, salt)
        zf.writestr(encrypted_entry, encrypted_bytes)

    def _process_directory(
        current_path: Path,
        parent_patterns: list[tuple[Path, Any]],
        zf: zipfile.ZipFile,
    ) -> None:
        if current_path.name == ".git":
            return
        current_patterns = list(parent_patterns)
        current_patterns.extend(load_gitignore_patterns(current_path))

        for item in current_path.iterdir():
            if is_ignored_by_gitignore(item, current_patterns):
                logger.info(
                    "🚫 除外: %s (.gitignore に一致)",
                    item.relative_to(target),
                )
                continue
            if item.is_dir():
                _process_directory(item, current_patterns, zf)
            elif item.is_file():
                rel = item.relative_to(target).as_posix()
                _add_file(zf, item, rel)

    try:
        with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_STORED) as zf:
            if target.is_file():
                _add_file(zf, target, target.name)
            elif target.is_dir():
                _process_directory(target, [], zf)
            else:
                msg = (
                    f"指定パス '{target}' はファイルまたはディレクトリではありません。"
                )
                raise ValueError(msg)  # noqa: TRY301

            metadata = {
                "version": METADATA_VERSION,
                "kdf": {"algorithm": "pbkdf2-sha256", "iterations": iterations},
                "file_mapping": file_mapping,
                "encrypt_filenames": encrypt_filenames,
            }
            metadata_json = json.dumps(metadata, ensure_ascii=False)
            encrypted_metadata = metadata_fernet.encrypt(metadata_json.encode("utf-8"))
            zf.writestr("metadata.encrypted", encrypted_metadata)
            zf.writestr("metadata.salt", metadata_salt)

    except Exception:
        if zip_filename and zip_filename.exists():
            zip_filename.unlink()
        raise

    return zip_filename


def _load_metadata(zf: zipfile.ZipFile, password: bytes) -> tuple[dict[str, Any], int]:
    """ZIPからメタデータを復号して返す。

    新フォーマット(version>=2)では metadata.kdf.iterations を信頼する。
    旧フォーマット(version なし)では LEGACY_PBKDF2_ITERATIONS を仮定する。
    新 iterations で失敗した場合は legacy で再試行する。

    Returns:
        tuple[dict[str, Any], int]: (metadata, per-file 復号に使う iterations)

    Raises:
        ValueError: メタデータの復号に失敗した場合
    """
    namelist = zf.namelist()

    if METADATA_ENCRYPTED_NAME not in namelist:
        msg = "暗号化ZIPファイルではありません。"
        raise ValueError(msg)

    if METADATA_SALT_NAME not in namelist:
        msg = "metadata.saltが見つかりません。ファイル破損の可能性があります。"
        raise ValueError(msg)

    encrypted_metadata = zf.read(METADATA_ENCRYPTED_NAME)
    metadata_salt = zf.read(METADATA_SALT_NAME)

    for iterations in (DEFAULT_PBKDF2_ITERATIONS, LEGACY_PBKDF2_ITERATIONS):
        key, _ = generate_key_from_password(password, metadata_salt, iterations)
        try:
            decrypted = Fernet(key).decrypt(encrypted_metadata)
        except InvalidToken:
            continue
        metadata: dict[str, Any] = json.loads(decrypted.decode("utf-8"))
        kdf = metadata.get("kdf") or {}
        raw_iterations = kdf.get("iterations", iterations)
        file_iterations = _validate_iterations(raw_iterations)
        return metadata, file_iterations

    msg = "パスワードが間違っています。"
    raise ValueError(msg)


def _validate_iterations(value: object) -> int:
    """メタデータの iterations をホワイトリスト検証する。

    Returns:
        検証済みの iterations

    Raises:
        ValueError: 値が許容リストに無い場合
    """
    if isinstance(value, bool) or not isinstance(value, int):
        msg = f"未対応の kdf.iterations です: {value!r}"
        raise ValueError(msg)  # noqa: TRY004 - untrusted ZIP metadata, uniform ValueError
    if value not in ALLOWED_PBKDF2_ITERATIONS:
        msg = f"未対応の kdf.iterations です: {value}"
        raise ValueError(msg)
    return value


def _validate_entry_paths(
    file_mapping: dict[str, str],
    extract_dir: Path,
) -> dict[str, Path]:
    """ZIP の全エントリパスを書き込み前に検証する。

    `_safe_join` が不正パス(絶対、'..'、親 symlink)を検出すると ValueError を伝播する。

    Returns:
        original_path -> 検証済みの最終出力パス の辞書
    """
    output_paths: dict[str, Path] = {}
    for original_path in file_mapping:
        output_paths[original_path] = _safe_join(extract_dir, original_path)
    return output_paths


def _decrypt_entry_to_path(
    zf: zipfile.ZipFile,
    encrypted_name: str,
    password: bytes,
    iterations: int,
    output_path: Path,
) -> None:
    """ZIP 内の暗号化エントリを復号して `output_path` に書き出す。

    Raises:
        ValueError: salt/encrypted エントリの欠落、または復号失敗
    """
    encrypted_filename = f"{encrypted_name}.encrypted"
    salt_filename = f"{encrypted_name}.salt"
    namelist = zf.namelist()

    if salt_filename not in namelist or encrypted_filename not in namelist:
        msg = f"ZIP からエントリが欠落しています: {encrypted_name}"
        raise ValueError(msg)

    salt = zf.read(salt_filename)
    encrypted_data = zf.read(encrypted_filename)

    key, _ = generate_key_from_password(password, salt, iterations)
    try:
        decrypted = Fernet(key).decrypt(encrypted_data)
    except InvalidToken as e:
        msg = "パスワードが間違っています。"
        raise ValueError(msg) from e

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(decrypted)


def _commit_one_file(  # noqa: PLR0913, PLR0917
    staging_path: Path,
    final_path: Path,
    extract_dir: Path,
    backup_dir: Path,
    backups: dict[Path, Path],
    placed_files: list[Path],
    created_dirs: list[Path],
) -> None:
    """Staging のファイルを最終位置へ移動する。既存ファイルは backup_dir に退避する。"""
    parent = final_path.parent
    missing_ancestors: list[Path] = []
    probe = parent
    extract_parent = extract_dir.parent
    while not probe.exists() and probe != extract_parent:
        missing_ancestors.append(probe)
        probe = probe.parent
    if missing_ancestors:
        parent.mkdir(parents=True, exist_ok=True)
        created_dirs.extend(reversed(missing_ancestors))

    if final_path.exists() or final_path.is_symlink():
        rel = final_path.relative_to(extract_dir)
        backup_path = backup_dir / rel
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        final_path.rename(backup_path)
        backups[final_path] = backup_path

    staging_path.rename(final_path)
    placed_files.append(final_path)


def _undo_placed_files(placed_files: list[Path], backups: dict[Path, Path]) -> None:
    for placed in placed_files:
        if placed in backups:
            continue
        if placed.exists() or placed.is_symlink():
            try:
                placed.unlink()
            except OSError:
                logger.exception("rollback: 配置ファイルの削除に失敗: %s", placed)


def _restore_backups(backups: dict[Path, Path]) -> None:
    for final_path, backup_path in backups.items():
        if not (backup_path.exists() or backup_path.is_symlink()):
            continue
        try:
            if final_path.exists() or final_path.is_symlink():
                final_path.unlink()
            backup_path.rename(final_path)
        except OSError:
            logger.exception(
                "rollback: バックアップの復元に失敗: %s ← %s",
                final_path,
                backup_path,
            )


def _rmdir_created_dirs(created_dirs: list[Path]) -> None:
    for d in sorted(created_dirs, key=lambda p: len(p.parts), reverse=True):
        if d.exists():
            with contextlib.suppress(OSError):
                d.rmdir()


def _rollback_extract(  # noqa: PLR0913, PLR0917
    placed_files: list[Path],
    backups: dict[Path, Path],
    created_dirs: list[Path],
    staging_dir: Path,
    backup_dir: Path,
    extract_dir: Path,
    extract_dir_pre_existed: bool,
) -> None:
    """途中失敗時に extract_dir を可能な限り元の状態に戻す。

    順序: 配置ファイル削除 → backup を rename で復元 → 新規作成 dir を rmdir
    → staging/backup dir を rmtree → pre-existed でなければ extract_dir も削除
    """
    _undo_placed_files(placed_files, backups)
    _restore_backups(backups)
    _rmdir_created_dirs(created_dirs)

    for d in (staging_dir, backup_dir):
        if d.exists():
            shutil.rmtree(d, ignore_errors=True)

    if not extract_dir_pre_existed and extract_dir.exists():
        shutil.rmtree(extract_dir, ignore_errors=True)


def extract_secure_encrypted_zip(
    zip_filepath: Path,
    password: bytes,
    extract_dir: Path | None = None,
) -> None:
    """暗号化ZIPを解凍し、内容とファイル名を復号する。

    既存の `extract_dir` への上書き解凍は merge セマンティクスで動作する:
    ZIP に含まれるファイルだけが対象になり、ZIP に含まれない既存ファイルは
    保護される。途中失敗時はバックアップから完全復元される。

    Args:
        zip_filepath: 解凍するZIPファイルのパス
        password: 復号パスワード
        extract_dir: 解凍先ディレクトリのパス(省略可能)

    Raises:
        FileNotFoundError: ZIPファイルが見つからない場合
        zipfile.BadZipFile: 無効なZIPファイルの場合
        ValueError: パスワードが間違っているか、エントリパスが不正な場合
    """
    if not zip_filepath.exists():
        msg = f"指定されたファイル '{zip_filepath}' が見つかりません。"
        raise FileNotFoundError(msg)

    try:
        with zipfile.ZipFile(zip_filepath, "r") as zf:
            if METADATA_ENCRYPTED_NAME not in zf.namelist():
                msg = (
                    f"'{zip_filepath}' は暗号化ZIPファイルではありません。"
                    "このプログラムで作成された暗号化ZIPファイルのみを"
                    "解凍できます。"
                )
                raise ValueError(msg)
    except zipfile.BadZipFile:
        msg = f"'{zip_filepath}' は有効なZIPファイルではありません。"
        raise zipfile.BadZipFile(msg) from None

    if extract_dir is None:
        extract_dir = zip_filepath.parent / zip_filepath.stem.replace("_encrypted", "")

    extract_dir_pre_existed = extract_dir.exists()
    rand = uuid.uuid4().hex[:12]
    staging_dir = extract_dir.parent / f".{extract_dir.name}.zipper-staging-{rand}"
    backup_dir = extract_dir.parent / f".{extract_dir.name}.zipper-bak-{rand}"

    placed_files: list[Path] = []
    backups: dict[Path, Path] = {}
    created_dirs: list[Path] = []

    try:
        with zipfile.ZipFile(zip_filepath, "r") as zf:
            metadata, file_iterations = _load_metadata(zf, password)
            file_mapping: dict[str, str] = metadata["file_mapping"]

            if not extract_dir_pre_existed:
                extract_dir.mkdir(parents=True, exist_ok=True)

            output_paths = _validate_entry_paths(file_mapping, extract_dir)

            staging_dir.mkdir(parents=True, exist_ok=True)
            staging_files: dict[str, Path] = {}
            for original_path, encrypted_name in file_mapping.items():
                staging_path = staging_dir / original_path
                _decrypt_entry_to_path(
                    zf, encrypted_name, password, file_iterations, staging_path
                )
                staging_files[original_path] = staging_path
                logger.info("✅ 復号完了: '%s'", original_path)

            for original_path, staging_path in staging_files.items():
                _commit_one_file(
                    staging_path,
                    output_paths[original_path],
                    extract_dir,
                    backup_dir,
                    backups,
                    placed_files,
                    created_dirs,
                )

        if backup_dir.exists():
            shutil.rmtree(backup_dir)
        if staging_dir.exists():
            shutil.rmtree(staging_dir)

    except BaseException:
        _rollback_extract(
            placed_files,
            backups,
            created_dirs,
            staging_dir,
            backup_dir,
            extract_dir,
            extract_dir_pre_existed,
        )
        raise
