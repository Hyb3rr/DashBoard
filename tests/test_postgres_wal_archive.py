import hashlib

import pytest

from scripts.ops.postgres_wal_archive import archive_wal


def test_wal_archive_is_atomic_idempotent_and_preserves_source(tmp_path, monkeypatch):
    source = tmp_path / "000000010000000000000001"
    source.write_bytes(b"wal-payload")
    spool = tmp_path / "spool"
    monkeypatch.setenv("POSTGRES_WAL_SPOOL_MIN_FREE_GIB", "0")

    first = archive_wal(source, spool_dir=spool)
    second = archive_wal(source, spool_dir=spool)

    assert first["status"] == "archived"
    assert second["status"] == "already_archived"
    assert (spool / source.name).read_bytes() == source.read_bytes()
    assert source.exists()
    assert not list(spool.glob("*.part"))
    assert first["sha256"] == hashlib.sha256(b"wal-payload").hexdigest()


def test_wal_archive_rejects_conflicting_existing_segment(tmp_path, monkeypatch):
    source = tmp_path / "000000010000000000000002"
    source.write_bytes(b"new")
    spool = tmp_path / "spool"
    spool.mkdir()
    (spool / source.name).write_bytes(b"different")
    monkeypatch.setenv("POSTGRES_WAL_SPOOL_MIN_FREE_GIB", "0")

    with pytest.raises(RuntimeError, match="conflicting WAL"):
        archive_wal(source, spool_dir=spool)
    assert source.read_bytes() == b"new"


def test_wal_archive_refuses_low_disk_floor(tmp_path, monkeypatch):
    source = tmp_path / "000000010000000000000003"
    source.write_bytes(b"wal")
    monkeypatch.setenv("POSTGRES_WAL_SPOOL_MIN_FREE_GIB", "1000000")

    with pytest.raises(RuntimeError, match="below safety floor"):
        archive_wal(source, spool_dir=tmp_path / "spool")
