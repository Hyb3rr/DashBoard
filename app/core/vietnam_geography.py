"""Vietnam-only province contract for post-2025 administrative geography."""

import json
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[2]
_PROVINCES = json.loads((_ROOT / "schemas/vietnam_provinces_2025.json").read_text(encoding="utf-8"))
_CROSSWALK = json.loads((_ROOT / "schemas/vietnam_province_crosswalk.json").read_text(encoding="utf-8"))
PROVINCES = tuple(_PROVINCES["units"])
_BY_CODE = {item["code"]: item for item in PROVINCES}
_OLD_BY_CODE = {item["old_code"]: item for item in _CROSSWALK["entries"]}


def canonical_province(code: str) -> dict:
    """Return a canonical 2025 province or raise ValueError for unknown codes."""
    key = str(code).zfill(2)
    try:
        return dict(_BY_CODE[key])
    except KeyError as exc:
        raise ValueError(f"Unknown Vietnam province code: {code}") from exc


def crosswalk_legacy_code(code: str) -> dict:
    """Resolve a pre-2025 province code without changing indicator values."""
    key = str(code).zfill(2)
    try:
        return dict(_OLD_BY_CODE[key])
    except KeyError as exc:
        raise ValueError(f"Unknown pre-2025 Vietnam province code: {code}") from exc


def aggregation_policy(indicator_type: str, relation: str) -> str:
    """Declare whether a historical indicator can be carried to the new unit."""
    if relation in {"unchanged", "renamed"}:
        return "identity"
    if indicator_type in {"count", "total", "amount", "stock"}:
        return "additive_only"
    return "requires_methodology"

