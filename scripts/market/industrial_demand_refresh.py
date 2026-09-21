"""CLI entry point for the evidence-only industrial demand refresh."""

from __future__ import annotations

import json

from app.db.market_repository import MarketRepository
from app.services.industrial_demand import refresh


if __name__ == "__main__":
    print(json.dumps(refresh(MarketRepository()), indent=2))
