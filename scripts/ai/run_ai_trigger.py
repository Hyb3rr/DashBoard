"""Run the opt-in semantic AI trigger consumer as a separate process."""

from __future__ import annotations

import argparse
import logging
import os
import signal
import time
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

from app.db import clickhouse as clickhouse_store
from app.db.ai_trigger import AiTriggerRepository, CursorGapError
from app.db.repositories import StateRepository
from app.services.ai_trigger_consumer import AiTriggerConsumer
from app.services.case_packets import build_live_case_packet
from app.routers.ip_state import _pg_item


LOGGER = logging.getLogger("ai_trigger")


def _enabled() -> bool:
    return os.getenv("AI_TRIGGER_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}


def _packet_loader(ip: str) -> dict:
    row = StateRepository().get(ip)
    if not row:
        raise LookupError(f"IP snapshot unavailable: {ip}")
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=1)
    traffic = clickhouse_store.traffic_for_ip(start, end, 3600, ip, os.getenv("DATASET_LIVE_ID", "live"))
    return build_live_case_packet(ip, _pg_item(row), traffic, start.isoformat(), end.isoformat())


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description="Run semantic AI change-feed trigger consumer")
    parser.add_argument("--enabled", action="store_true", help="Explicitly enable automatic job creation")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-interval", type=float, default=float(os.getenv("AI_TRIGGER_POLL_INTERVAL_SECONDS", "2")))
    parser.add_argument("--batch-size", type=int, default=int(os.getenv("AI_TRIGGER_BATCH_SIZE", "50")))
    args = parser.parse_args()
    enabled = args.enabled or _enabled()
    repository = AiTriggerRepository()
    consumer = AiTriggerConsumer(repository, _packet_loader, enabled=True, batch_size=args.batch_size)
    if not enabled:
        LOGGER.info("AI semantic trigger disabled; exiting without reading change feed")
        return 0
    stopping = False

    def stop(*_signals):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping:
        try:
            if not repository.auto_explain_enabled():
                time.sleep(max(0.2, args.poll_interval))
                continue
            created = consumer.run_once()
            if args.once:
                return 0
            if created:
                LOGGER.info("created %s AI explanation job(s)", created)
        except CursorGapError:
            LOGGER.exception("AI trigger stopped: retained change-feed gap")
            return 2
        except Exception:
            LOGGER.exception("AI trigger cycle failed; cursor was not advanced for the failed event")
            if args.once:
                return 1
        time.sleep(max(0.2, args.poll_interval))
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    raise SystemExit(main())
