"""Pure policy for product/industry demand evidence.

This module deliberately has no database, network, clock, or framework
dependency. Adapters provide normalized mappings and evidence rows; callers
persist the returned immutable-shaped dictionaries as snapshots.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping


SELLABLE_PRODUCT_COUNT = 14
MAPPING_TYPES = {"direct", "industry_proxy", "unverified"}
GEO_SCOPES = {"country", "geo_unit"}


def load_matrix(path: str | Path) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as handle:
        matrix = json.load(handle)
    validate_matrix(matrix)
    return matrix


def validate_matrix(matrix: Mapping[str, Any]) -> None:
    if matrix.get("schema_version") != "market-demand-v2":
        raise ValueError("unsupported product-industry matrix version")
    if matrix.get("scoring") != "evidence_only":
        raise ValueError("market-demand v2 must remain evidence-only")
    products = matrix.get("products")
    if not isinstance(products, list) or len(products) != SELLABLE_PRODUCT_COUNT:
        raise ValueError(f"matrix must contain exactly {SELLABLE_PRODUCT_COUNT} sellable products")
    ids: set[str] = set()
    for product in products:
        required = ("product_id", "display_name", "category", "processes", "industries",
                    "hs_codes", "mapping_type", "rationale", "source_refs", "status")
        missing = [key for key in required if not product.get(key)]
        if missing:
            raise ValueError(f"product mapping missing {missing}: {product.get('product_id')}")
        product_id = product["product_id"]
        if product_id in ids:
            raise ValueError(f"duplicate product mapping: {product_id}")
        ids.add(product_id)
        if product["mapping_type"] not in MAPPING_TYPES:
            raise ValueError(f"unsupported mapping type: {product['mapping_type']}")
        if product["category"] not in {"woodworking", "metalworking"}:
            raise ValueError(f"unsupported product category: {product['category']}")
    proxy = matrix.get("industry_proxy") or {}
    if proxy.get("product_id") in ids or proxy.get("role") != "evidence_only":
        raise ValueError("industry proxy must be evidence-only and outside sellable products")


def evidence_id(evidence: Mapping[str, Any]) -> str:
    """Return a deterministic identity for evidence content, excluding its id."""
    identity = {key: evidence[key] for key in sorted(evidence) if key != "evidence_id"}
    encoded = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "demand_" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:24]


def normalize_evidence(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one source observation and assign its stable identity.

    A province/geo-unit observation must originate at geo-unit resolution. A
    country observation is retained as country context and cannot be relabeled
    as a province observation by this policy.
    """
    required = ("source_id", "source_geo_scope", "observed_period", "collected_at",
                "mapping_version", "limitations")
    missing = [key for key in required if key not in raw or raw[key] in (None, "")]
    if missing:
        raise ValueError(f"evidence missing required fields: {missing}")
    scope = raw["source_geo_scope"]
    if scope not in GEO_SCOPES:
        raise ValueError(f"unsupported source geography: {scope}")
    geo_unit_id = raw.get("geo_unit_id")
    if geo_unit_id and scope != "geo_unit":
        raise ValueError("country evidence cannot be assigned to a geo unit")
    if not geo_unit_id and scope == "geo_unit":
        raise ValueError("geo-unit evidence requires geo_unit_id")
    if "observed_value" not in raw:
        raise ValueError("evidence must include observed_value; use null for missing data")
    if not isinstance(raw["limitations"], list):
        raise ValueError("evidence limitations must be a list")
    result = dict(raw)
    result["evidence_id"] = evidence_id(result)
    return result


def coverage(evidence: Iterable[Mapping[str, Any]], applicable_count: int | None = None) -> dict[str, Any]:
    """Count observed evidence without converting missing values to zero."""
    rows = list(evidence)
    observed = sum(row.get("observed_value") is not None for row in rows)
    total = applicable_count if applicable_count is not None else len(rows)
    if total < observed or total < 0:
        raise ValueError("applicable evidence count is inconsistent")
    return {"observed": observed, "total": total,
            "ratio": round(observed / total, 4) if total else 0.0,
            "missing": max(0, total - observed)}


def build_profiles(matrix: Mapping[str, Any], evidence: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Group validated evidence by product while preserving missing coverage."""
    validate_matrix(matrix)
    product_ids = {item["product_id"] for item in matrix["products"]}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in evidence:
        normalized = normalize_evidence(row)
        product_id = normalized.get("product_id")
        if product_id is not None and product_id not in product_ids:
            raise ValueError(f"evidence references unknown sellable product: {product_id}")
        if product_id is not None:
            grouped[product_id].append(normalized)
    result = []
    for product in sorted(matrix["products"], key=lambda item: item["product_id"]):
        rows = grouped.get(product["product_id"], [])
        result.append({"product_id": product["product_id"],
                       "display_name": product["display_name"],
                       "category": product["category"],
                       "processes": list(product["processes"]),
                       "industries": list(product["industries"]),
                       "evidence": rows,
                       "coverage": coverage(rows)})
    return result
