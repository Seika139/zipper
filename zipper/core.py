import base64
import json
import logging
import os
import shutil
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
ALLOWED_PBKDF2_ITERATIONS = frozenset(
    {LEGACY_PBKDF2_ITERATIONS, DEFAULT_PBKDF2_ITERATIONS}
)
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


def _load_metadata(
    zf: zipfile.ZipFile, password: bytes
) -> tuple[dict[str, Any], int]:
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


def _decrypt_single_file(  # noqa: PLR0913, PLR0917
    zf: zipfile.ZipFile,
    original_path: str,
    encrypted_name: str,
    password: bytes,
    extract_dir: Path,
    created_paths: set[Path],
    iterations: int,
) -> None:
    """ZIP内の1ファイルを復号して書き出す。

    Raises:
        ValueError: 復号に失敗した場合(パスワード不正)
    """
    encrypted_filename = f"{encrypted_name}.encrypted"
    salt_filename = f"{encrypted_name}.salt"
    namelist = zf.namelist()

    if salt_filename not in namelist or encrypted_filename not in namelist:
        logger.warning("ソルトまたはファイル欠落: %s", original_path)
        return

    salt = zf.read(salt_filename)
    temp_encrypted = extract_dir / "temp_encrypted"

    output_file_path = _safe_join(extract_dir, original_path)

    parent = output_file_path.parent
    missing_ancestors: list[Path] = []
    probe = parent
    while not probe.exists():
        missing_ancestors.append(probe)
        probe = probe.parent
    if missing_ancestors:
        parent.mkdir(parents=True, exist_ok=True)
        created_paths.update(missing_ancestors)

    try:
        Path(temp_encrypted).write_bytes(zf.read(encrypted_filename))
        created_paths.add(temp_encrypted)
        decrypt_file(temp_encrypted, output_file_path, password, salt, iterations)
        created_paths.add(output_file_path)
        logger.info("✅ 復号完了: '%s'", original_path)
    except InvalidToken as e:
        msg = "パスワードが間違っています。"
        raise ValueError(msg) from e
    finally:
        if temp_encrypted.exists():
            temp_encrypted.unlink()


def extract_secure_encrypted_zip(
    zip_filepath: Path,
    password: bytes,
    extract_dir: Path | None = None,
) -> None:
    """暗号化ZIPを解凍し、内容とファイル名を復号する。

    Args:
        zip_filepath: 解凍するZIPファイルのパス
        password: 復号パスワード
        extract_dir: 解凍先ディレクトリのパス(省略可能)

    Raises:
        FileNotFoundError: ZIPファイルが見つからない場合
        zipfile.BadZipFile: 無効なZIPファイルの場合
        ValueError: パスワードが間違っている場合
    """
    if not zip_filepath.exists():
        msg = f"指定されたファイル '{zip_filepath}' が見つかりません。"
        raise FileNotFoundError(msg)

    try:
        with zipfile.ZipFile(zip_filepath, "r") as zf:
            if "metadata.encrypted" not in zf.namelist():
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

    created_paths: set[Path] = set()

    def cleanup() -> None:
        for p in sorted(created_paths, key=lambda x: len(x.parts), reverse=True):
            if p.exists():
                if p.is_file():
                    p.unlink()
                else:
                    shutil.rmtree(p)

    try:
        if not extract_dir.exists():
            extract_dir.mkdir(parents=True, exist_ok=True)
            created_paths.add(extract_dir)

        with zipfile.ZipFile(zip_filepath, "r") as zf:
            metadata, file_iterations = _load_metadata(zf, password)
            file_mapping = metadata["file_mapping"]

            for original_path, encrypted_name in file_mapping.items():
                _decrypt_single_file(
                    zf,
                    original_path,
                    encrypted_name,
                    password,
                    extract_dir,
                    created_paths,
                    file_iterations,
                )

    except BaseException:
        cleanup()
        raise
