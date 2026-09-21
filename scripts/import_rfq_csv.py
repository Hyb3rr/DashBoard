"""Validate and import sales history CSV without inferring geo/product mappings."""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from app.db.market_repository import MarketRepository
from scripts.market.fx_rates import ExchangeRateHostClient, FxRateError

load_dotenv()


REQUIRED = {"geo_unit_id", "product_id", "customer_name", "stage", "created_at"}
STAGES = {"rfq", "quoted", "negotiating", "won", "lost"}


def _date_from_timestamp(value: str) -> str | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        return None


def validate_rows(rows: list[dict[str, str]], valid_geo_units: set[str], valid_products: set[str],
                  fx_resolver: Any = None) -> tuple[list[dict[str, str]], Counter]:
    accepted, rejected = [], Counter()
    for row in rows:
        row = {key: (value or "").strip() for key, value in row.items()}
        missing = REQUIRED - row.keys() | {key for key in REQUIRED if not row.get(key)}
        if missing:
            rejected["missing_required"] += 1
        elif row["geo_unit_id"] not in valid_geo_units:
            rejected["missing_geo"] += 1
        elif row["product_id"] not in valid_products:
            rejected["missing_product"] += 1
        elif row["stage"] not in STAGES:
            rejected["invalid_stage"] += 1
        else:
            try:
                value = Decimal(row["deal_value_original"]) if row.get("deal_value_original") else None
                fx = Decimal(row["fx_rate_used"]) if row.get("fx_rate_used") else None
                if value is not None:
                    currency = row.get("deal_value_currency", "").upper()
                    row["deal_value_currency"] = currency
                    if len(currency) != 3 or not currency.isalpha():
                        raise ValueError
                    if currency == "USD" and fx is None:
                        fx, row["fx_rate_used"] = Decimal("1"), "1"
                    if currency == "USD" and fx == 1 and not row.get("fx_rate_provider"):
                        row["fx_rate_provider"] = "identity_usd"
                    row["fx_rate_date"] = row.get("fx_rate_date") or _date_from_timestamp(row.get("quoted_at", "")) or _date_from_timestamp(row.get("created_at", ""))
                    if not row["fx_rate_date"]:
                        raise ValueError
                    if fx is None and currency != "USD" and fx_resolver is not None:
                        fx = Decimal(str(fx_resolver(currency, row["fx_rate_date"])))
                        row["fx_rate_used"] = str(fx)
                        row["fx_rate_provider"] = "exchangerate.host"
                    if fx is None or not row.get("fx_rate_provider"):
                        raise LookupError
                if value is not None and value < 0:
                    raise ValueError
                if fx is not None and fx <= 0:
                    raise ValueError
            except (LookupError, FxRateError):
                rejected["missing_fx_rate"] += 1
            except (InvalidOperation, ValueError):
                rejected["invalid_value_or_fx"] += 1
            else:
                accepted.append(row)
    return accepted, rejected


def import_csv(path: Path, repo: MarketRepository) -> dict[str, Any]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    geo_units, products = repo.list_market_identity_keys()
    accepted, rejected = validate_rows(rows, geo_units, products, ExchangeRateHostClient().get_rate)
    imported = repo.upsert_rfq_intake(accepted)
    return {"read": len(rows), "accepted": len(accepted), "imported": imported,
            "rejected": dict(rejected)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path", type=Path)
    args = parser.parse_args()
    print(import_csv(args.csv_path, MarketRepository()))


if __name__ == "__main__":
    main()
