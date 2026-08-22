"""Re-resolve every IP already stored in geo_resolutions."""
from app.db.postgres import transaction
from app.db.pg_intelligence import resolve_network_location
from app.db.repositories import GeoRepository
from psycopg.types.json import Jsonb

with transaction() as conn:
    ips = [str(row["ip"]) for row in conn.execute("SELECT ip FROM geo_resolutions").fetchall()]

updated = 0
for ip in ips:
    data = resolve_network_location(ip, force_refresh=True)
    GeoRepository().persist_resolution(ip, data)
    network_location = dict(data)
    with transaction() as conn:
        conn.execute("""UPDATE ip_profiles
            SET country=%s, country_code=%s, city=%s, latitude=%s, longitude=%s,
                network_location=%s, location_confidence=%s, location_disputed=%s,
                location_scope=%s, geo_sources=%s, geo_resolved_at=now(), updated_at=now()
            WHERE ip=%s""", (
            data.get("country"), data.get("country_code"), data.get("city"),
            data.get("latitude"), data.get("longitude"), Jsonb(network_location),
            int(data.get("confidence", 0) or 0), bool(data.get("disputed")),
            data.get("scope"), Jsonb(data.get("sources", [])), ip))
    updated += 1
    if updated % 1000 == 0:
        print(f"updated={updated}")
print(f"updated={updated}")
