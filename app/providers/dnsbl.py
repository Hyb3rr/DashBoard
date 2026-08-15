from __future__ import annotations
import ipaddress
import socket
from datetime import datetime, timezone

def query_ip(conn, ip: str, zones: list[str], threshold: int = 1) -> dict:
    address=ipaddress.ip_address(ip)
    if not address.is_global: return {"status":"skipped", "score":0}
    score=0; evidence=[]
    for zone in zones:
        query=f"{address.reverse_pointer}.{zone}"
        try:
            answers=socket.gethostbyname_ex(query)[2]
            code=int(answers[0].split(".")[3]) if answers else 0
            weight=3 if code in (2,3) else 2 if code in (4,5,6,7) else 1 if code else 0
            if weight: score += weight; evidence.append({"zone":zone,"code":code,"weight":weight})
        except socket.gaierror: continue
    if score >= threshold:
        now=datetime.now(timezone.utc).isoformat()
        conn.execute("""INSERT INTO threat_indicators(network,source,category,confidence,checked_at,evidence_json,active) VALUES(?,?,?,?,?,?,1)
          ON CONFLICT(network,source,category) DO UPDATE SET confidence=excluded.confidence,checked_at=excluded.checked_at,evidence_json=excluded.evidence_json,active=1""",
          (ip,"dnsbl","dnsbl",score,now,__import__('json').dumps(evidence)))
        conn.commit()
    return {"status":"flagged" if score >= threshold else "clean", "score":score, "evidence":evidence}
