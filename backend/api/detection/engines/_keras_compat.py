"""
Forward-compatibility shim for ``.keras`` files saved by a newer Keras.

The DL artifacts in ``dl_models/*.keras`` were saved with Keras 3.13.2.
The project's venv runs Python 3.10, which can't install Keras >=3.13
(those wheels require Python >=3.11), so the runtime tops out at Keras
3.12.1. Two known additive keys in the 3.13 saved-config schema break
3.12's deserializer with ``Unrecognized keyword arguments``:

* Dense layer config: ``quantization_config: None``
* InputLayer config: ``optional: False``

Both default to a value that is a no-op for our inference path, so we
can strip them without altering model semantics. This module loads a
``.keras`` file, edits its in-memory ``config.json``, writes a patched
zip alongside the original (cached so we only do the surgery once),
and lets Keras load that.

If a future Keras version introduces other forward-incompatible keys
beyond these two, ``_PATCHABLE_KEYS`` should be extended.
"""
from __future__ import annotations

import io
import json
import logging
import shutil
import zipfile
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger("pids.detection.dl.compat")

# (class_name -> set of forward-only keys to strip from layer config)
_PATCHABLE_KEYS: Dict[str, set] = {
    "Dense": {"quantization_config"},
    "EinsumDense": {"quantization_config"},
    "InputLayer": {"optional"},
}


def _strip_keys(node: Any) -> None:
    """
    Recursively walk a Keras saved-model config dict and strip any
    forward-incompatible keys we know about. Mutates ``node`` in place.
    """
    if isinstance(node, dict):
        # The serialized format wraps every layer/object as
        # ``{"class_name": ..., "config": {...}}``. Identify those
        # nodes and strip from their inner config.
        cls_name = node.get("class_name")
        cfg = node.get("config")
        if isinstance(cls_name, str) and isinstance(cfg, dict):
            for k in _PATCHABLE_KEYS.get(cls_name, set()):
                cfg.pop(k, None)
        # Recurse.
        for v in node.values():
            _strip_keys(v)
    elif isinstance(node, list):
        for item in node:
            _strip_keys(item)


def patched_keras_path(original: Path) -> Path:
    """
    Return a path to a patched copy of ``original`` that any keys in
    :data:`_PATCHABLE_KEYS` have been stripped out of.

    The patched file is written next to the original with a
    ``.compat.keras`` suffix so subsequent loads skip the surgery. If
    the original has no offending keys, the cache file is still
    produced (idempotent — same bytes).
    """
    original = Path(original)
    patched = original.with_suffix(".compat.keras")

    # Re-patch if the source is newer than the cached patch (or cache missing).
    if patched.exists() and patched.stat().st_mtime >= original.stat().st_mtime:
        return patched

    with zipfile.ZipFile(original, "r") as src_zip:
        # Read everything into memory. .keras files are small (tens of MB).
        members = {name: src_zip.read(name) for name in src_zip.namelist()}

    if "config.json" not in members:
        # Not a Keras 3 saved-model archive — bail gracefully and let the
        # caller fall back to a vanilla load (which will surface the real
        # error if any).
        logger.warning(
            "patched_keras_path: %s has no config.json; not patching", original
        )
        shutil.copyfile(original, patched)
        return patched

    cfg = json.loads(members["config.json"].decode("utf-8"))
    _strip_keys(cfg)
    members["config.json"] = json.dumps(cfg).encode("utf-8")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out_zip:
        for name, data in members.items():
            out_zip.writestr(name, data)
    patched.write_bytes(buf.getvalue())
    logger.info("Wrote forward-compat patched Keras file: %s", patched)
    return patched


def load_keras_compat(path: Path, **load_kwargs: Any) -> Any:
    """
    Load a ``.keras`` model with the forward-compat patch applied.

    Falls back to a direct Keras load if the runtime is new enough to
    accept the original file as-is.
    """
    import keras  # standalone Keras 3
    path = Path(path)
    try:
        return keras.models.load_model(str(path), **load_kwargs)
    except (TypeError, ValueError) as exc:
        # Only patch on the specific deserialization failures we know
        # about — anything else is a real model error worth raising.
        msg = str(exc)
        if "Unrecognized keyword" not in msg and "could not be deserialized" not in msg:
            raise
        logger.info(
            "Direct Keras load of %s failed (%s); applying forward-compat patch",
            path.name, type(exc).__name__,
        )
        patched = patched_keras_path(path)
        return keras.models.load_model(str(patched), **load_kwargs)
