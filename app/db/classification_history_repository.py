"""Durable PostgreSQL history for classification state transitions."""

from __future__ import annotations

from typing import Any

from .json_codec import jsonb_value
from .postgres import transaction


class ClassificationHistoryRepository:
    """Persist and query bounded per-IP classification transition history."""

    @staticmethod
    def record_transition(
        conn,
        *,
        event_key: str,
        dataset_id: str,
        ip: str,
        source: str,
        changed_at,
        previous_classification: dict[str, Any],
        current_classification: dict[str, Any],
    ) -> None:
        """Insert one label transition idempotently in its owner's transaction."""
        if previous_classification.get("label") == current_classification.get("label"):
            return
        conn.execute(
            """INSERT INTO ip_classification_history
               (event_key,dataset_id,ip,source,changed_at,previous_classification,current_classification)
               VALUES (%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (event_key) DO NOTHING""",
            (
                event_key, dataset_id, ip, source, changed_at,
                jsonb_value(previous_classification), jsonb_value(current_classification),
            ),
        )

    def for_ip(self, ip: str, limit: int = 20) -> list[dict[str, Any]]:
        """Return the newest bounded transition snapshots for one IP."""
        bounded_limit = min(max(int(limit), 1), 100)
        with transaction() as conn:
            rows = conn.execute(
                """SELECT id,event_key,dataset_id,host(ip) AS ip,source,changed_at,
                          previous_classification,current_classification
                     FROM ip_classification_history
                    WHERE ip=%s::inet
                    ORDER BY changed_at DESC,id DESC
                    LIMIT %s""",
                (ip, bounded_limit),
            ).fetchall()
        return [dict(row) for row in rows]
