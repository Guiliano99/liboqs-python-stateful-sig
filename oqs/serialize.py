"""
Serialization and deserialization of stateful signature keys
using OneAsymmetricKey (PKCS#8) structure.
"""

import argparse
import logging
import os
from pathlib import Path
from typing import Iterable, Union

from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ, tag

import oqs
from pyasn1_alt_modules import rfc5958

_CACHE_ENV_VAR = "LIBOQS_STATEFUL_SIG_KEY_DIR"
_NAME_2_OIDS = {
    "hss": "1.2.840.113549.1.9.16.3.17",  # RFC 9708
    "xmss": "1.3.6.1.5.5.7.6.34",  # RFC 9802
    "xmssmt": "1.3.6.1.5.5.7.6.35",  # RFC 9802
}
_OID_2_NAME = {v: k for k, v in _NAME_2_OIDS.items()}


def _get_default_cache_dir() -> Path:
    """Return the platform-appropriate cache directory for stateful keys."""

    env_dir = os.environ.get(_CACHE_ENV_VAR)
    if env_dir:
        return Path(env_dir).expanduser()

    if os.name == "nt":
        base_dir = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base_dir = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))

    return base_dir / "liboqs-python" / "stateful_sig_keys"


STATEFUL_SIG_KEY_DIR = _get_default_cache_dir()
_KEY_DIR = STATEFUL_SIG_KEY_DIR


def _get_oid_from_name(name: str) -> str:
    """Get the OID corresponding to the stateful signature name."""
    if name.startswith("LMS"):
        return _NAME_2_OIDS["hss"]
    if name.startswith("XMSS-"):
        return _NAME_2_OIDS["xmss"]
    if name.startswith("XMSSMT-"):
        return _NAME_2_OIDS["xmssmt"]
    msg = f"Unsupported stateful signature name: {name}"
    raise ValueError(msg)


def serialize_stateful_signature_key(
    stateful_sig: oqs.StatefulSignature, public_key: bytes, fpath: Union[str, Path]
) -> None:
    """
    Serialize the stateful signature key to a `OneAsymmetricKey` structure.

    :param stateful_sig: The stateful signature object.
    :param public_key: The public key bytes.
    :param fpath: The file path to save the serialized key.
    """
    one_asym_key = rfc5958.OneAsymmetricKey()
    one_asym_key["version"] = 1
    one_asym_key["privateKeyAlgorithm"]["algorithm"] = univ.ObjectIdentifier(
        _get_oid_from_name(stateful_sig.method_name.decode())
    )
    one_asym_key["privateKey"] = stateful_sig.export_secret_key()
    one_asym_key["publicKey"] = (
        rfc5958.PublicKey()
        .fromOctetString(public_key)
        .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))
    )

    der_data = encoder.encode(one_asym_key)
    fpath_obj = Path(fpath)
    fpath_obj.parent.mkdir(parents=True, exist_ok=True)
    with fpath_obj.open("wb") as f:
        f.write(der_data)
    logging.info("Wrote: %s", fpath_obj.name)


def deserialize_stateful_signature_key(
    key_name: str, dir_name: Union[str, Path] = _KEY_DIR
) -> tuple[bytes, bytes]:
    """
    Deserialize the stateful signature key from a `OneAsymmetricKey` structure.

    :param key_name: The base name of the serialized key (without extension).
    :param dir_name: The directory where the key files are stored.
    :return: A tuple (private_key_bytes, public_key_bytes).
    """
    key_name = key_name.replace("/", "_layers_", 1).lower()
    dir_path = Path(dir_name).expanduser()
    fpath = dir_path / f"{key_name}.der"

    with fpath.open("rb") as f:
        der_data = f.read()

    one_asym_key = decoder.decode(der_data, asn1Spec=rfc5958.OneAsymmetricKey())[0]
    oid = str(one_asym_key["privateKeyAlgorithm"]["algorithm"])

    # Accept any OID for supported families
    if oid not in _OID_2_NAME:
        msg = f"Unsupported stateful signature OID: {oid}"
        raise ValueError(msg)

    private_key_bytes = one_asym_key["privateKey"].asOctets()
    public_key_bytes = one_asym_key["publicKey"].asOctets()
    return private_key_bytes, public_key_bytes

def gen_or_load_stateful_signature_key(
    key_name: str,
    dir_name: Union[str, Path] = _KEY_DIR,
    *,
    force_generate: bool = False,
) -> tuple[bytes, bytes]:
    """
    Generate or load a stateful signature key pair.

    :param key_name: The name of the stateful signature mechanism.
    :param dir_name: The directory where the key files are stored.
    :param force_generate: Force key regeneration even if cached material exists.
    :return: A tuple (private_key_bytes, public_key_bytes).
    """
    key_file_name = key_name.replace("/", "_layers_", 1).lower()
    dir_path = Path(dir_name).expanduser()
    fpath = dir_path / f"{key_file_name}.der"

    if not force_generate and fpath.exists():
        return deserialize_stateful_signature_key(key_name, dir_name=dir_path)

    dir_path.mkdir(parents=True, exist_ok=True)
    with oqs.StatefulSignature(key_name) as stfl_sig:
        public_key_bytes = stfl_sig.generate_keypair()
        private_key_bytes = stfl_sig.export_secret_key()
        serialize_stateful_signature_key(stfl_sig, public_key_bytes, fpath)
    return private_key_bytes, public_key_bytes


def ensure_cached_stateful_signature_keys(
    algorithms: Iterable[str],
    dir_name: Union[str, Path] = _KEY_DIR,
    *,
    force: bool = False,
) -> list[Path]:
    """Ensure that stateful signature keys for the given algorithms are cached."""

    dir_path = Path(dir_name).expanduser()
    generated_paths: list[Path] = []
    for algorithm in algorithms:
        key_file_name = algorithm.replace("/", "_layers_", 1).lower()
        target_path = dir_path / f"{key_file_name}.der"
        existed = target_path.exists()
        gen_or_load_stateful_signature_key(
            algorithm, dir_name=dir_path, force_generate=force
        )
        if force or not existed:
            logging.info("Cached stateful signature key for %s at %s", algorithm, target_path)
            generated_paths.append(target_path)
        else:
            logging.info("Reusing cached stateful signature key for %s at %s", algorithm, target_path)
    return generated_paths


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(
        description="Generate and cache liboqs stateful signature keys."
    )
    parser.add_argument(
        "-a",
        "--algorithm",
        action="append",
        dest="algorithms",
        help=(
            "Stateful signature algorithm to cache. May be specified multiple times. "
            "Defaults to all enabled mechanisms."
        ),
    )
    parser.add_argument(
        "-d",
        "--directory",
        dest="directory",
        help=(
            "Directory used to cache keys. Defaults to the environment variable "
            f"{_CACHE_ENV_VAR} if set, otherwise {STATEFUL_SIG_KEY_DIR}."
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Regenerate keys even if cached copies already exist.",
    )
    args = parser.parse_args()

    cache_dir = (
        Path(args.directory).expanduser()
        if args.directory
        else STATEFUL_SIG_KEY_DIR
    )
    algs = (
        list(args.algorithms)
        if args.algorithms
        else list(oqs.get_enabled_stateful_sig_mechanisms())
    )
    ensure_cached_stateful_signature_keys(algs, dir_name=cache_dir, force=args.force)
    logging.info(
        "Ensured %d stateful signature key(s) in %s",
        len(algs),
        cache_dir,
    )
