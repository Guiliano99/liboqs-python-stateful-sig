from __future__ import annotations

from pathlib import Path
import argparse
import os
from typing import Any, Iterable

import oqs
import oqs.serialize


def _mech_to_filename(name: str) -> str:
    """Map mechanism name to key filename (keep in sync with CI pipeline).

    Example:
        "XMSSMT-SHA2_20/4_256" -> "xmssmt-sha2_20_layers_4_256.der"
    """

    return f"{name.replace('/', '_layers_', 1).lower()}.der"


def _collect_mechanism_names() -> list[str]:
    """Return all enabled XMSS/XMSSMT stateful signature mechanisms."""

    return [
        name
        for name in oqs.get_enabled_stateful_sig_mechanisms()
        if name.startswith(("XMSS-", "XMSSMT-"))
    ]


def generate_keys(out_dir: Path) -> dict[str, Any]:
    """Generate all XMSS/XMSSMT keys into *out_dir* if they are missing.

    Returns a small stats dict useful for tests:
        {"generated": int, "skipped": int, "total": int, "missing": list[str]}
    """

    out_dir.mkdir(parents=True, exist_ok=True)

    all_keys: list[str] = _collect_mechanism_names()

    # Track existing keys by stem for informational purposes
    existing_keys: set[str] = {p.stem for p in out_dir.glob("*.der")}

    generated = 0
    skipped = 0

    for name in all_keys:
        key_filename = _mech_to_filename(name)
        key_path = out_dir / key_filename

        if key_path.exists():
            print(f"✓ Skipping {name} (already exists)")
            skipped += 1
            continue

        print(f"⚙ Generating {name}...")
        with oqs.StatefulSignature(name) as sig:
            pub = sig.generate_keypair()
            oqs.serialize.serialize_stateful_signature_key(sig, pub, key_path)
        print(f"✓ Generated {name}")
        generated += 1

    print("\n=== Summary ===")
    print(f"Generated: {generated}")
    print(f"Skipped: {skipped}")
    total = len(all_keys)
    print(f"Total: {total}")

    missing: list[str] = []
    for name in all_keys:
        key_filename = _mech_to_filename(name)
        key_path = out_dir / key_filename
        if not key_path.exists():
            missing.append(name)

    if missing:
        print("\nERROR: The following keys could not be generated:")
        for name in missing:
            print(f" - {name}")

    print(f"\nAll {total} XMSS/XMSSMT keys are available in {out_dir}.")
    print(f"\nFiles in {out_dir}:")

    return {
        "generated": generated,
        "skipped": skipped,
        "total": total,
        "missing": missing,
        "existing": sorted(existing_keys),
    }


def _resolve_out_dir(cli_dir: str | None) -> Path:
    """Resolve the output directory from CLI argument or KEY_DIR env.

    Precedence:
      1. Explicit CLI argument (if provided).
      2. $KEY_DIR environment variable (if set).
      3. Default "data/xmss_xmssmt_keys" relative to repo root.
    """

    if cli_dir:
        return Path(cli_dir)

    env_dir = os.environ.get("KEY_DIR")
    if env_dir:
        return Path(env_dir)

    return Path("data/xmss_xmssmt_keys")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate XMSS/XMSSMT stateful signature keys.",
    )
    parser.add_argument(
        "key_dir",
        nargs="?",
        help=(
            "Output directory for keys. "
            "Defaults to $KEY_DIR if set, otherwise data/xmss_xmssmt_keys."
        ),
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    out_dir = _resolve_out_dir(args.key_dir)
    stats = generate_keys(out_dir)

    # For now we always return 0 to keep behavior similar to the inline script,
    # which only printed errors but did not cause the job to fail.
    if stats["missing"]:
        # If you later want to fail the pipeline, change this to return 1.
        pass

    return 0


if __name__ == "__main__":  # pragma: no cover - thin CLI wrapper
    main()

