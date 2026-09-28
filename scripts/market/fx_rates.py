"""Historical FX lookup with per-import caching for RFQ backfills."""

from __future__ import annotations

import json
import os
from decimal import Decimal
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class FxRateError(RuntimeError):
    """Raised when a historical FX rate cannot be obtained safely."""


class ExchangeRateHostClient:
    provider = "exchangerate.host"

    def __init__(self, access_key: str | None = None, endpoint: str | None = None):
        """Configure the provider client and initialize its per-instance cache."""
        self.access_key = access_key or os.getenv("FX_RATE_API_KEY", "")
        self.endpoint = endpoint or os.getenv("FX_RATE_API_URL", "https://api.exchangerate.host/historical")
        self._cache: dict[tuple[str, str], Decimal] = {}

    def get_rate(self, currency: str, date: str) -> Decimal:
        """Return a cached or fetched historical exchange rate against USD."""
        currency = currency.upper().strip()
        key = (currency, date)
        if key in self._cache:
            return self._cache[key]
        if not self.access_key:
            raise FxRateError("FX_RATE_API_KEY is required for exchangerate.host")
        query = urlencode({"access_key": self.access_key, "date": date,
                           "source": currency, "currencies": "USD"})
        request = Request(f"{self.endpoint}?{query}", headers={"Accept": "application/json"})
        try:
            with urlopen(request, timeout=15) as response:
                payload = json.load(response)
        except Exception as exc:  # noqa: BLE001 - normalize provider/network failures
            raise FxRateError(f"FX provider request failed for {currency}/{date}") from exc
        if payload.get("success") is False:
            raise FxRateError("FX provider returned an error")
        rate = (payload.get("rates") or {}).get("USD")
        if rate is None:
            rate = (payload.get("quotes") or {}).get(f"{currency}USD")
        try:
            parsed = Decimal(str(rate))
        except Exception as exc:  # noqa: BLE001 - reject malformed provider data
            raise FxRateError("FX provider returned no usable USD rate") from exc
        if parsed <= 0:
            raise FxRateError("FX provider returned a non-positive USD rate")
        self._cache[key] = parsed
        return parsed
